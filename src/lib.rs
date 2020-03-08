//! Recursive digest for filesystem path content
use std::marker::PhantomData;
use std::{
    collections::HashSet,
    fs,
    io::BufRead,
    path::{Path, PathBuf},
};
use thiserror::Error;

/// Re-export `walkdir`
pub use walkdir;

/// Read file content into a `digest::Digest`
fn read_file_to_digest_input(path: &Path, input: &mut impl digest::Digest) -> std::io::Result<()> {
    let file = fs::File::open(path)?;

    let mut reader = std::io::BufReader::new(file);

    loop {
        let length = {
            let buffer = reader.fill_buf()?;
            input.input(buffer);
            buffer.len()
        };
        if length == 0 {
            break;
        }
        reader.consume(length);
    }

    Ok(())
}

#[derive(Debug, Error)]
pub enum DigestError {
    #[error("could not convert OsStr string to utf8")]
    OsStrConversionError,
    #[error("io Error: {}", _0)]
    IoError(std::io::Error),
    #[error("walkdir Error: {}", _0)]
    WalkdirError(walkdir::Error),
    #[error("an entry that was supposed to be a file, contains sub-entries")]
    FileWithSubentriesError,
    #[error("file not supported: {}", _0)]
    FileNotSupported(String),
}

impl From<std::io::Error> for DigestError {
    fn from(err: std::io::Error) -> Self {
        DigestError::IoError(err)
    }
}

impl From<walkdir::Error> for DigestError {
    fn from(err: walkdir::Error) -> Self {
        DigestError::WalkdirError(err)
    }
}

/// Handle passed to the user to add optional path data
pub struct AdditionalDataWriter<'a, D> {
    used: bool,
    hasher: &'a mut D,
}

impl<'a, D> AdditionalDataWriter<'a, D>
where
    D: digest::Digest,
{
    pub fn input(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            if !self.used {
                self.hasher.input(&[0]);
                self.used = true;
            }
            self.hasher.input(bytes);
        }
    }
}

pub struct RecursiveDigestBuilder<Digest, FFilter, FAData> {
    filter: FFilter,
    additional_data: FAData,
    digest: std::marker::PhantomData<Digest>,
}

impl<Digest, FFilter, FAData> RecursiveDigestBuilder<Digest, FFilter, FAData>
where
    FFilter: Fn(&walkdir::DirEntry) -> bool,
    FAData: Fn(&mut AdditionalDataWriter<'_, Digest>) -> Result<(), DigestError>,
{
    /// Set filter function just like [`walkdir::IntoIterator::filter_entry`]
    pub fn filter<F: Fn(&walkdir::DirEntry) -> bool>(
        self,
        filter: F,
    ) -> RecursiveDigestBuilder<Digest, F, FAData> {
        RecursiveDigestBuilder {
            filter,
            additional_data: self.additional_data,
            digest: self.digest,
        }
    }

    pub fn additional_data<
        F: Fn(&mut AdditionalDataWriter<'_, Digest>) -> Result<(), DigestError>,
    >(
        self,
        f: F,
    ) -> RecursiveDigestBuilder<Digest, FFilter, F> {
        RecursiveDigestBuilder {
            filter: self.filter,
            additional_data: f,
            digest: self.digest,
        }
    }

    pub fn build(self) -> RecursiveDigest<Digest, FFilter, FAData> {
        RecursiveDigest {
            digest: self.digest,
            filter: self.filter,
            additional_data: self.additional_data,
        }
    }
}

/// Recursive Digest
///
/// Can calculate a recursive digest for a path
pub struct RecursiveDigest<Digest, FFilter, FAData> {
    digest: PhantomData<Digest>,
    filter: FFilter,
    additional_data: FAData,
}

impl<Digest>
    RecursiveDigest<
        Digest,
        Box<dyn Fn(&walkdir::DirEntry) -> bool>,
        Box<dyn Fn(&mut AdditionalDataWriter<'_, Digest>) -> Result<(), DigestError>>,
    >
where
    Digest: digest::Digest + digest::FixedOutput,
{
    /// Create `RecursiveDigest` by configuring `RecursiveDigestBuilder`
    pub fn new() -> RecursiveDigestBuilder<
        Digest,
        Box<dyn Fn(&walkdir::DirEntry) -> bool>,
        Box<dyn Fn(&mut AdditionalDataWriter<'_, Digest>) -> Result<(), DigestError>>,
    > {
        RecursiveDigestBuilder {
            filter: Box::new(|_| true),
            additional_data: Box::new(|_| Ok(())),
            digest: PhantomData,
        }
    }
}

impl<Digest, FFilter, FAData> RecursiveDigest<Digest, FFilter, FAData>
where
    FFilter: Fn(&walkdir::DirEntry) -> bool,
    FAData: Fn(&mut AdditionalDataWriter<'_, Digest>) -> Result<(), DigestError>,
    Digest: digest::Digest + digest::FixedOutput,
{
    pub fn get_digest_of(&mut self, root_path: &Path) -> Result<Vec<u8>, DigestError> {
        let mut hashers = vec![];

        // pop the top hasher and output it to the one just above it
        fn flush_up_one_level<D: digest::Digest + digest::FixedOutput>(hashers: &mut Vec<D>) {
            let hasher = hashers.pop().expect("must not be empty yet");
            hashers
                .last_mut()
                .expect("must not happen")
                .input(hasher.fixed_result().as_slice());
        }

        let base_depth = root_path.components().count();

        let mut first = true;
        for entry in walkdir::WalkDir::new(root_path)
            .follow_links(false)
            .sort_by(|a, b| a.path().cmp(b.path()))
            .into_iter()
            .filter_entry(|entry| {
                // can't skip the `root_path`
                if first {
                    debug_assert_eq!(root_path, entry.path());
                    first = false;
                    return true;
                }

                (self.filter)(entry)
            })
        {
            let entry = entry?;
            let entry_depth = entry.path().components().count();

            debug_assert!(base_depth <= entry_depth);
            let depth = entry_depth - base_depth;
            let hasher_size_required = depth + 1;

            // we finished with (potentially multiple levels of) recursive content
            // in the previous iterations, now:
            // we flush it upwards, and replace the top one with a fresh one
            while hasher_size_required <= hashers.len() {
                flush_up_one_level(&mut hashers);
            }
            hashers.push(Digest::new());

            debug_assert_eq!(hashers.len(), hasher_size_required);

            let file_type = entry.file_type();

            // top level directory includes only content, no name or additional_data
            // names and additional data go the hasher above the one we just prepared
            if 0 < depth {
                let hasher = hashers.get_mut(depth - 1).expect("must not happen");

                let mut name_hasher = Digest::new();
                // name
                if cfg!(target_os = "unix") {
                    use std::os::unix::ffi::OsStrExt;
                    name_hasher.input(
                        entry
                            .path()
                            .file_name()
                            .expect("must have a file_name")
                            .as_bytes(),
                    );
                } else {
                    name_hasher.input(
                        entry
                            .path()
                            .file_name()
                            .expect("must have a file_name")
                            .to_string_lossy()
                            .as_bytes(),
                    );
                }
                // additional data (optional)
                (self.additional_data)(&mut AdditionalDataWriter {
                    hasher,
                    used: false,
                })?;
                hasher.input(name_hasher.fixed_result().as_slice());
            }

            // content
            if file_type.is_file() {
                self.read_content_of_file(
                    entry.path(),
                    hashers.last_mut().expect("must not happen"),
                )?;
            } else if file_type.is_symlink() {
                self.read_content_of_symlink(
                    entry.path(),
                    hashers.last_mut().expect("must not happen"),
                )?;
            } else if file_type.is_dir() {
                hashers.last_mut().expect("must not happen").input(b"D");
            } else {
                return Err(DigestError::FileNotSupported(
                    entry.path().display().to_string(),
                ));
            }
        }

        loop {
            if hashers.len() == 1 {
                return Ok(hashers
                    .pop()
                    .expect("must not fail")
                    .fixed_result()
                    .to_vec());
            }
            flush_up_one_level(&mut hashers);
        }
    }

    fn read_content_of_file(
        &self,
        full_path: &Path,
        parent_hasher: &mut Digest,
    ) -> Result<(), DigestError> {
        parent_hasher.input(b"F");
        read_file_to_digest_input(full_path, parent_hasher)?;
        Ok(())
    }

    fn read_content_of_symlink(
        &self,
        full_path: &Path,
        parent_hasher: &mut Digest,
    ) -> Result<(), DigestError> {
        parent_hasher.input(b"L");
        parent_hasher.input(
            full_path
                .read_link()?
                .to_str()
                .ok_or(DigestError::OsStrConversionError)?
                .as_bytes(),
        );
        Ok(())
    }
}

#[deprecated]
pub fn get_recursive_digest_for_paths<Digest: digest::Digest + digest::FixedOutput, H>(
    root_path: &Path,
    paths: HashSet<PathBuf, H>,
) -> Result<Vec<u8>, DigestError>
where
    H: std::hash::BuildHasher,
{
    let mut h = RecursiveDigest::<Digest, _, _>::new()
        .filter(|entry| {
            let rel_path = entry
                .path()
                .strip_prefix(&root_path)
                .expect("must be prefix");
            paths.contains(rel_path)
        })
        .build();

    h.get_digest_of(root_path)
}

#[deprecated]
pub fn get_recursive_digest_for_dir<
    Digest: digest::Digest + digest::FixedOutput,
    H: std::hash::BuildHasher,
>(
    root_path: &Path,
    rel_path_ignore_list: &HashSet<PathBuf, H>,
) -> Result<Vec<u8>, DigestError> {
    let mut h = RecursiveDigest::<Digest, _, _>::new()
        .filter(|entry| {
            let rel_path = entry
                .path()
                .strip_prefix(&root_path)
                .expect("must be prefix");
            !rel_path_ignore_list.contains(rel_path)
        })
        .build();

    h.get_digest_of(root_path)
}
