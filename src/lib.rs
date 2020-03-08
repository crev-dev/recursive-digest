use std::marker::PhantomData;
use std::{
    collections::HashSet,
    fs,
    io::BufRead,
    path::{Path, PathBuf},
};
use thiserror::Error;

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

pub struct AdditionalData<'a, D> {
    hasher: &'a mut D,
}

impl<'a, D> AdditionalData<'a, D>
where
    D: digest::Digest,
{
    pub fn input(&mut self, bytes: &[u8]) {
        self.hasher.input(bytes);
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
    FAData: Fn(&mut AdditionalData<'_, Digest>) -> Result<(), DigestError>,
{
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

    pub fn additional_data<F: Fn(&mut AdditionalData<'_, Digest>) -> Result<(), DigestError>>(
        self,
        f: F,
    ) -> RecursiveDigestBuilder<Digest, FFilter, F> {
        RecursiveDigestBuilder {
            filter: self.filter,
            additional_data: f,
            digest: self.digest,
        }
    }

    fn build(self) -> RecursiveDigest<Digest, FFilter, FAData> {
        RecursiveDigest {
            digest: self.digest,
            filter: self.filter,
            additional_data: self.additional_data,
        }
    }
}
pub struct RecursiveDigest<Digest, FFilter, FAData> {
    digest: PhantomData<Digest>,
    filter: FFilter,
    additional_data: FAData,
}

impl<Digest>
    RecursiveDigest<
        Digest,
        Box<dyn Fn(&walkdir::DirEntry) -> bool>,
        Box<dyn Fn(&mut AdditionalData<'_, Digest>) -> Result<(), DigestError>>,
    >
where
    Digest: digest::Digest + digest::FixedOutput,
{
    fn new() -> RecursiveDigestBuilder<
        Digest,
        Box<dyn Fn(&walkdir::DirEntry) -> bool>,
        Box<dyn Fn(&mut AdditionalData<'_, Digest>) -> Result<(), DigestError>>,
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
    FAData: Fn(&mut AdditionalData<'_, Digest>) -> Result<(), DigestError>,
    Digest: digest::Digest + digest::FixedOutput,
{
    fn get_digest(&mut self, root_path: &Path) -> Result<Vec<u8>, DigestError> {
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

        for entry in walkdir::WalkDir::new(root_path)
            .follow_links(false)
            .sort_by(|a, b| a.path().cmp(b.path()))
            .into_iter()
            .filter_entry(&self.filter)
        {
            let entry = entry?;
            let entry_depth = entry.path().components().count();

            debug_assert!(base_depth <= entry_depth);
            let depth = entry_depth - base_depth;
            let hasher_size_required = depth + 1;

            // we're at the same level, which means we
            // iterating over a second file in a directory,
            // flush it out as a content
            // we will go deeper again in next `if` expression
            if hashers.len() == hasher_size_required {
                flush_up_one_level(&mut hashers);
            }

            // we go deeper: only one level at the time though
            if hashers.len() < hasher_size_required {
                hashers.push(Digest::new());
            }

            // we finished with (potentially multiple levels of) recursive content
            while hasher_size_required < hashers.len() {
                flush_up_one_level(&mut hashers);
            }

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
                hasher.input(name_hasher.fixed_result().as_slice());
                // additional data (optional)
                (self.additional_data)(&mut AdditionalData { hasher })?;
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

pub fn get_recursive_digest_for_paths<Digest: digest::Digest + digest::FixedOutput, H>(
    root_path: &Path,
    paths: HashSet<PathBuf, H>,
) -> Result<Vec<u8>, DigestError>
where
    H: std::hash::BuildHasher,
{
    let empty_path = Path::new("");
    let mut h = RecursiveDigest::<Digest, _, _>::new()
        .filter(|entry| {
            let rel_path = strip_root_path_if_included(&root_path, entry.path());
            rel_path == empty_path || paths.contains(rel_path)
        })
        .build();

    h.get_digest(root_path.into())
}

pub fn get_recursive_digest_for_dir<
    Digest: digest::Digest + digest::FixedOutput,
    H: std::hash::BuildHasher,
>(
    root_path: &Path,
    rel_path_ignore_list: &HashSet<PathBuf, H>,
) -> Result<Vec<u8>, DigestError> {
    dbg!(root_path);
    dbg!(rel_path_ignore_list);
    let mut h = RecursiveDigest::<Digest, _, _>::new()
        .filter(|entry| {
            let rel_path = strip_root_path_if_included(&root_path, entry.path());
            dbg!(rel_path);
            !rel_path_ignore_list.contains(rel_path)
        })
        .build();

    h.get_digest(root_path.into())
}

fn strip_root_path_if_included<'a>(root_path: &Path, path: &'a Path) -> &'a Path {
    path.strip_prefix(&root_path).expect("must be prefix")
}

#[test]
fn test_strip_root_path_if_included() {
    let root_path = Path::new("some/root/path");

    // Should strip the root path here
    let path_with_root = Path::new("some/root/path/and/subfolder");
    assert_eq!(
        strip_root_path_if_included(&root_path, path_with_root),
        Path::new("and/subfolder")
    );
}
