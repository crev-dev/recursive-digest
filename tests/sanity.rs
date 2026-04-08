use crev_recursive_digest::{DigestError, RecursiveDigest};
use digest::consts::U64;
use digest::Digest;
use std::{
    collections::HashSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use tempdir::TempDir;

type Blake2b512 = blake2::Blake2b<U64>;

/// Manual H(data) helper
fn h(data: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Blake2b512::new();
    for d in data {
        hasher.update(d);
    }
    hasher.finalize().to_vec()
}

fn digest_all(root: &Path) -> Result<Vec<u8>, DigestError> {
    RecursiveDigest::<Blake2b512, _, _>::new()
        .build()
        .get_digest_of(root)
}

fn digest_excluding(root: &Path, excluded: HashSet<PathBuf>) -> Result<Vec<u8>, DigestError> {
    let root_owned = root.to_path_buf();
    RecursiveDigest::<Blake2b512, _, _>::new()
        .filter(move |entry| {
            let rel_path = entry
                .path()
                .strip_prefix(&root_owned)
                .expect("walkdir yields paths under root");
            !excluded.contains(rel_path)
        })
        .build()
        .get_digest_of(root)
}

fn digest_including(root: &Path, included: HashSet<PathBuf>) -> Result<Vec<u8>, DigestError> {
    let root_owned = root.to_path_buf();
    RecursiveDigest::<Blake2b512, _, _>::new()
        .filter(move |entry| {
            let rel_path = entry
                .path()
                .strip_prefix(&root_owned)
                .expect("walkdir yields paths under root");
            included.contains(rel_path)
        })
        .build()
        .get_digest_of(root)
}

#[test]
fn sanity() -> Result<(), DigestError> {
    let tmp_dir = TempDir::new("recursive-digest-test")?;

    let msg = b"foo";

    // Directory "recursive-digest-test/a/"
    let dir_path = tmp_dir.path().join("a");
    fs::create_dir_all(&dir_path)?;

    // File "recursive-digest-test/a/foo"
    let file_in_dir_path = dir_path.join("foo");
    let mut file_in_dir = fs::File::create(file_in_dir_path)?;
    file_in_dir.write_all(msg)?;
    drop(file_in_dir);

    // File "recursive-digest-test/b"
    let file_path = tmp_dir.path().join("b");
    let mut file = fs::File::create(&file_path)?;
    file.write_all(msg)?;
    drop(file);

    let file_digest = digest_all(&file_path)?;

    let mut hasher = Blake2b512::new();
    hasher.update(b"F");
    hasher.update(msg);

    let standalone_file_digest = hasher.finalize().to_vec();

    assert_eq!(&file_digest, &standalone_file_digest);
    // captured by `echo  -ne "Ffoo" | b2sum`
    assert_eq!(
        hex::encode(&standalone_file_digest),
        "e41c3b6ac2b512af3a14eb11faed1486f693ce3bd3606afbe458e183ae4e1080a4209f44ada1c186920f541d41a192eaa654fee6792a6ac008f44f783a59176d"
    );

    let dir_digest = digest_all(&dir_path)?;
    assert_ne!(&dir_digest, &standalone_file_digest);
    let mut hasher = Blake2b512::new();
    hasher.update(b"D");
    hasher.update(
        hex::decode(
            "ca002330e69d3e6b84a46a56a6533fd79d51d97a3bb7cad6c2ff43b354185d6dc1e723fb3db4ae0737e120378424c714bb982d9dc5bbd7a0ab318240ddd18f8d"
        ).unwrap()
    );

    hasher.update(&file_digest);

    let manual_dir_digest = hasher.finalize().to_vec();
    assert_eq!(&dir_digest, &manual_dir_digest);

    Ok(())
}

#[cfg(target_family = "windows")]
pub fn symlink_file<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(src, dst)
}

#[cfg(target_family = "unix")]
pub fn symlink_file<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> std::io::Result<()> {
    std::os::unix::fs::symlink(src, dst)
}

/// Captured by:
///
/// ```
/// mkdir -p /tmp/a/b/c/d/e/f/g
/// ln -sf /tmp/a/b/c/d/e/f/g/h "../../a"
/// rblake2sum /tmp/a
/// ```
///
/// Ignored by default on Windows, as users typically cannot create symlinks
/// without running as admin.
#[test]
#[cfg_attr(target_family = "windows", ignore)]
fn backward_comp() -> Result<(), DigestError> {
    let tmp_dir = TempDir::new("recursive-digest-test2")?;

    let dir_path = tmp_dir.path().join("a");
    let path = dir_path.clone();
    let path = path.join("b");
    let path = path.join("c");
    let path = path.join("d");
    let path = path.join("e");
    let path = path.join("f");
    let path = path.join("g");
    fs::create_dir_all(&path)?;

    symlink_file(std::path::PathBuf::from("../../a"), path.join("h"))?;

    let dir_digest = digest_all(&dir_path)?;

    assert_eq!(
        hex::encode(dir_digest),
        "bc97399633e1228a563d57adecf98810364526a8e7bfc24b89985c5607e77605575d10989d5954b762af45c498129854dca603688fd63bd580bbf952c650b735"
    );
    tmp_dir.into_path();
    Ok(())
}

#[test]
fn test_file_digest() -> Result<(), DigestError> {
    let tmp_dir = TempDir::new("recursive-digest-test3")?;
    let foo_content = b"foo_content";
    let file_in_dir_path = tmp_dir.path().join("foo");
    let mut file_in_dir = fs::File::create(&file_in_dir_path)?;
    file_in_dir.write_all(foo_content)?;

    let expected = {
        let mut hasher = Blake2b512::new();
        hasher.update(b"F");
        hasher.update(foo_content);
        hasher.finalize().to_vec()
    };

    assert_eq!(digest_all(&file_in_dir_path)?, expected);

    Ok(())
}

#[test]
// Tests the inclusion and exclusion of paths.
fn test_exclude_include_path() -> Result<(), DigestError> {
    let tmp_dir = TempDir::new("recursive-digest-test3")?;

    let foo_content = b"foo_content";
    let file_in_dir_path = tmp_dir.path().join("foo");
    let mut file_in_dir = fs::File::create(file_in_dir_path)?;
    file_in_dir.write_all(foo_content)?;

    let bar_content = b"bar_content";
    let file_in_dir_path_2 = tmp_dir.path().join("bar");
    let mut file_in_dir_2 = fs::File::create(file_in_dir_path_2)?;
    file_in_dir_2.write_all(bar_content)?;

    let expected = {
        let mut hasher = Blake2b512::new();
        hasher.update(b"F");
        hasher.update(bar_content);
        let file_sum = hasher.finalize().to_vec();

        let mut hasher = Blake2b512::new();
        hasher.update(b"bar");
        let dir_sum = hasher.finalize().to_vec();

        let mut hasher = Blake2b512::new();
        hasher.update(b"D");
        hasher.update(dir_sum);
        hasher.update(file_sum);
        hasher.finalize().to_vec()
    };

    let mut excluded = HashSet::new();
    excluded.insert(Path::new("foo").to_path_buf());
    assert_eq!(digest_excluding(tmp_dir.path(), excluded)?, expected);

    let mut included = HashSet::new();
    included.insert(Path::new("bar").to_path_buf());
    assert_eq!(digest_including(tmp_dir.path(), included)?, expected);

    Ok(())
}

#[test]
fn ignore_dir() -> Result<(), DigestError> {
    let tmp_dir = TempDir::new("recursive-digest-test-ignore-dir")?;

    let d1 = tmp_dir.path().join("d1");
    let d2 = tmp_dir.path().join("d2");

    fs::create_dir_all(d1.join("a/b1/c/d"))?;
    fs::create_dir_all(d1.join("a/b2/c/d"))?;
    fs::create_dir_all(&d2)?;

    let mut excluded_a = HashSet::new();
    excluded_a.insert(PathBuf::from("a"));

    assert_eq!(
        digest_excluding(&d1, excluded_a)?,
        digest_all(&d2)?,
    );
    Ok(())
}

#[test]
fn additional_data_folded_into_name_hash() -> Result<(), DigestError> {
    // Verify that additional_data is folded into the per-entry name hash
    // as H(name || 0 || data), matching the README, rather than written
    // separately to the parent hasher.
    type Blake2b512 = blake2::Blake2b<U64>;

    let tmp_dir = TempDir::new("recursive-digest-test-adata")?;
    let dir_path = tmp_dir.path().join("d");
    fs::create_dir_all(&dir_path)?;
    let file_path = dir_path.join("f");
    fs::File::create(&file_path)?.write_all(b"hello")?;

    let extra = b"role=owner";

    let digest = RecursiveDigest::<Blake2b512, _, _>::new()
        .additional_data(|_entry, writer| {
            writer.input(extra);
            Ok(())
        })
        .build()
        .get_digest_of(&dir_path)?;

    // Reference computation per README:
    //   file_hash = H("F" || file_content)
    //   name_hash = H("f" || 0 || extra)
    //   dir_hash  = H("D" || name_hash || file_hash)
    let file_hash = {
        let mut h = Blake2b512::new();
        h.update(b"F");
        h.update(b"hello");
        h.finalize().to_vec()
    };
    let name_hash = {
        let mut h = Blake2b512::new();
        h.update(b"f");
        h.update([0]);
        h.update(extra);
        h.finalize().to_vec()
    };
    let expected = {
        let mut h = Blake2b512::new();
        h.update(b"D");
        h.update(&name_hash);
        h.update(&file_hash);
        h.finalize().to_vec()
    };

    assert_eq!(digest, expected);
    Ok(())
}

// --- New comprehensive tests ---

/// Empty file: H("F")
#[test]
fn empty_file() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-empty-file")?;
    let path = tmp.path().join("empty");
    fs::File::create(&path)?;

    assert_eq!(digest_all(&path)?, h(&[b"F"]));
    Ok(())
}

/// Empty directory: H("D")
#[test]
fn empty_directory() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-empty-dir")?;
    let path = tmp.path().join("d");
    fs::create_dir(&path)?;

    assert_eq!(digest_all(&path)?, h(&[b"D"]));
    Ok(())
}

/// Symlink inside a dir: H("L" || symlink_target)
/// (Symlinks can't be the walkdir root — they must be entries inside a directory.)
#[test]
#[cfg_attr(target_family = "windows", ignore)]
fn symlink_manual_digest() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-symlink")?;
    let dir = tmp.path().join("d");
    fs::create_dir(&dir)?;
    symlink_file("some/target", dir.join("lnk"))?;

    let expected = h(&[
        b"D",
        &h(&[b"lnk"]),
        &h(&[b"L", b"some/target"]),
    ]);
    assert_eq!(digest_all(&dir)?, expected);
    Ok(())
}

/// The type prefix ensures file, dir, and symlink produce different digests
/// even when the raw content bytes are the same.
#[test]
#[cfg_attr(target_family = "windows", ignore)]
fn type_prefix_distinguishes_file_dir_symlink() -> Result<(), DigestError> {
    // We can verify this directly from the manual hash computations.
    let file_hash = h(&[b"F", b"D"]);
    let dir_hash = h(&[b"D"]);
    let link_hash = h(&[b"L", b"D"]);

    assert_ne!(file_hash, dir_hash);
    assert_ne!(file_hash, link_hash);
    assert_ne!(dir_hash, link_hash);

    // Also verify against actual digests for file and dir.
    let tmp = TempDir::new("rd-type-prefix")?;

    let f = tmp.path().join("f");
    fs::File::create(&f)?.write_all(b"D")?;
    assert_eq!(digest_all(&f)?, file_hash);

    let d = tmp.path().join("d");
    fs::create_dir(&d)?;
    assert_eq!(digest_all(&d)?, dir_hash);

    // Symlink tested inside a directory to avoid root-stat issue.
    let parent = tmp.path().join("p");
    fs::create_dir(&parent)?;
    symlink_file("D", parent.join("lnk"))?;
    let parent_digest = digest_all(&parent)?;
    let expected = h(&[b"D", &h(&[b"lnk"]), &link_hash]);
    assert_eq!(parent_digest, expected);

    Ok(())
}

/// Directory with two files — verify sorted-by-name order.
///
/// dir/
///   aaa  -> "one"
///   zzz  -> "two"
///
/// Expected: H("D" || H("aaa") || H("F"||"one") || H("zzz") || H("F"||"two"))
#[test]
fn dir_two_files_sorted() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-two-files")?;
    let dir = tmp.path().join("dir");
    fs::create_dir(&dir)?;
    fs::File::create(dir.join("aaa"))?.write_all(b"one")?;
    fs::File::create(dir.join("zzz"))?.write_all(b"two")?;

    let expected = h(&[
        b"D",
        &h(&[b"aaa"]),
        &h(&[b"F", b"one"]),
        &h(&[b"zzz"]),
        &h(&[b"F", b"two"]),
    ]);

    assert_eq!(digest_all(&dir)?, expected);
    Ok(())
}

/// Sorting is byte-order, so uppercase letters come before lowercase.
/// 'B' (0x42) < 'a' (0x61)
#[test]
fn sort_is_byte_order() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-byte-sort")?;
    let dir = tmp.path().join("dir");
    fs::create_dir(&dir)?;
    fs::File::create(dir.join("a"))?.write_all(b"1")?;
    fs::File::create(dir.join("B"))?.write_all(b"2")?;

    // Byte order: 'B' (0x42) before 'a' (0x61)
    let expected = h(&[
        b"D",
        &h(&[b"B"]),
        &h(&[b"F", b"2"]),
        &h(&[b"a"]),
        &h(&[b"F", b"1"]),
    ]);

    assert_eq!(digest_all(&dir)?, expected);
    Ok(())
}

/// Nested directory: dir/sub/file
///
/// inner = H("D" || H("file") || H("F"||"data"))
/// outer = H("D" || H("sub")  || inner)
#[test]
fn nested_directory() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-nested")?;
    let dir = tmp.path().join("outer");
    fs::create_dir_all(dir.join("sub"))?;
    fs::File::create(dir.join("sub").join("file"))?.write_all(b"data")?;

    let inner = h(&[b"D", &h(&[b"file"]), &h(&[b"F", b"data"])]);
    let expected = h(&[b"D", &h(&[b"sub"]), &inner]);

    assert_eq!(digest_all(&dir)?, expected);
    Ok(())
}

/// Three levels deep: a/b/c/f
#[test]
fn three_levels_deep() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-deep")?;
    let root = tmp.path().join("a");
    fs::create_dir_all(root.join("b/c"))?;
    fs::File::create(root.join("b/c/f"))?.write_all(b"x")?;

    let c_hash = h(&[b"D", &h(&[b"f"]), &h(&[b"F", b"x"])]);
    let b_hash = h(&[b"D", &h(&[b"c"]), &c_hash]);
    let expected = h(&[b"D", &h(&[b"b"]), &b_hash]);

    assert_eq!(digest_all(&root)?, expected);
    Ok(())
}

/// Mixed content: directory containing a file, a subdir, and a symlink.
///
/// root/
///   dir/     (empty)
///   file     -> "hi"
///   link     -> "target"
///
/// Sorted: dir, file, link
#[test]
#[cfg_attr(target_family = "windows", ignore)]
fn mixed_file_dir_symlink() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-mixed")?;
    let root = tmp.path().join("root");
    fs::create_dir_all(root.join("dir"))?;
    fs::File::create(root.join("file"))?.write_all(b"hi")?;
    symlink_file("target", root.join("link"))?;

    let expected = h(&[
        b"D",
        &h(&[b"dir"]),
        &h(&[b"D"]), // empty subdir
        &h(&[b"file"]),
        &h(&[b"F", b"hi"]),
        &h(&[b"link"]),
        &h(&[b"L", b"target"]),
    ]);

    assert_eq!(digest_all(&root)?, expected);
    Ok(())
}

/// Renaming a file changes the digest (name is part of the hash).
#[test]
fn rename_changes_digest() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-rename")?;
    let d1 = tmp.path().join("d1");
    let d2 = tmp.path().join("d2");
    fs::create_dir(&d1)?;
    fs::create_dir(&d2)?;
    fs::File::create(d1.join("alpha"))?.write_all(b"x")?;
    fs::File::create(d2.join("beta"))?.write_all(b"x")?;

    assert_ne!(digest_all(&d1)?, digest_all(&d2)?);
    Ok(())
}

/// Two directories with identical content produce the same digest.
#[test]
fn identical_dirs_same_digest() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-identical")?;
    let d1 = tmp.path().join("d1");
    let d2 = tmp.path().join("d2");
    for d in [&d1, &d2] {
        fs::create_dir_all(d.join("sub"))?;
        fs::File::create(d.join("a"))?.write_all(b"hello")?;
        fs::File::create(d.join("sub/b"))?.write_all(b"world")?;
    }

    assert_eq!(digest_all(&d1)?, digest_all(&d2)?);
    Ok(())
}

/// File content matters — same name, different content.
#[test]
fn different_content_different_digest() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-diff-content")?;
    let d1 = tmp.path().join("d1");
    let d2 = tmp.path().join("d2");
    fs::create_dir(&d1)?;
    fs::create_dir(&d2)?;
    fs::File::create(d1.join("f"))?.write_all(b"aaa")?;
    fs::File::create(d2.join("f"))?.write_all(b"bbb")?;

    assert_ne!(digest_all(&d1)?, digest_all(&d2)?);
    Ok(())
}

/// additional_data with empty input is a no-op (no 0-byte separator written).
#[test]
fn additional_data_empty_is_noop() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-adata-empty")?;
    let dir = tmp.path().join("d");
    fs::create_dir(&dir)?;
    fs::File::create(dir.join("f"))?.write_all(b"v")?;

    let without = digest_all(&dir)?;

    let with_empty = RecursiveDigest::<Blake2b512, _, _>::new()
        .additional_data(|_entry, writer| {
            writer.input(b""); // empty — should be no-op
            Ok(())
        })
        .build()
        .get_digest_of(&dir)?;

    assert_eq!(without, with_empty);
    Ok(())
}

/// additional_data applied to a subdirectory entry, not just a file.
#[test]
fn additional_data_on_subdir() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-adata-subdir")?;
    let root = tmp.path().join("root");
    let sub = root.join("sub");
    fs::create_dir_all(&sub)?;

    let extra = b"meta";

    let digest = RecursiveDigest::<Blake2b512, _, _>::new()
        .additional_data(|_entry, writer| {
            writer.input(extra);
            Ok(())
        })
        .build()
        .get_digest_of(&root)?;

    // H(entry_name || 0 || extra) for the "sub" entry
    let name_hash = h(&[b"sub", &[0], extra]);
    let sub_content = h(&[b"D"]); // empty subdir
    let expected = h(&[b"D", &name_hash, &sub_content]);

    assert_eq!(digest, expected);
    Ok(())
}

/// Multiple additional_data inputs are concatenated after the single 0-byte separator.
/// H(name || 0 || chunk1 || chunk2)
#[test]
fn additional_data_multiple_inputs() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-adata-multi")?;
    let dir = tmp.path().join("d");
    fs::create_dir(&dir)?;
    fs::File::create(dir.join("f"))?.write_all(b"v")?;

    let digest = RecursiveDigest::<Blake2b512, _, _>::new()
        .additional_data(|_entry, writer| {
            writer.input(b"aaa");
            writer.input(b"bbb");
            Ok(())
        })
        .build()
        .get_digest_of(&dir)?;

    // The 0 separator is written once, then both chunks follow
    let name_hash = h(&[b"f", &[0], b"aaa", b"bbb"]);
    let file_hash = h(&[b"F", b"v"]);
    let expected = h(&[b"D", &name_hash, &file_hash]);

    assert_eq!(digest, expected);
    Ok(())
}

/// Root-level entry has no name or additional_data hashed — only its content.
/// So additional_data callback is called but has no effect on root.
#[test]
fn additional_data_ignored_for_root() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-adata-root")?;
    let dir = tmp.path().join("d");
    fs::create_dir(&dir)?;
    // empty dir, no children — additional_data never triggers because
    // root is at depth 0

    let without = digest_all(&dir)?;

    let with_extra = RecursiveDigest::<Blake2b512, _, _>::new()
        .additional_data(|_entry, writer| {
            writer.input(b"should-not-matter-for-root");
            Ok(())
        })
        .build()
        .get_digest_of(&dir)?;

    assert_eq!(without, with_extra);
    Ok(())
}

/// Directory with many entries verifies correct sorted concatenation.
///
/// dir/ contains files: c, a, b (created out of order)
/// Sorted: a, b, c
#[test]
fn many_entries_sorted_correctly() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-many-sorted")?;
    let dir = tmp.path().join("dir");
    fs::create_dir(&dir)?;
    // Create out of alphabetical order
    fs::File::create(dir.join("c"))?.write_all(b"3")?;
    fs::File::create(dir.join("a"))?.write_all(b"1")?;
    fs::File::create(dir.join("b"))?.write_all(b"2")?;

    let expected = h(&[
        b"D",
        &h(&[b"a"]),
        &h(&[b"F", b"1"]),
        &h(&[b"b"]),
        &h(&[b"F", b"2"]),
        &h(&[b"c"]),
        &h(&[b"F", b"3"]),
    ]);

    assert_eq!(digest_all(&dir)?, expected);
    Ok(())
}

/// Sibling directories: verify each subdir is digested independently.
///
/// root/
///   x/  -> contains file "f" with "X"
///   y/  -> empty
#[test]
fn sibling_directories() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-siblings")?;
    let root = tmp.path().join("root");
    fs::create_dir_all(root.join("x"))?;
    fs::create_dir_all(root.join("y"))?;
    fs::File::create(root.join("x/f"))?.write_all(b"X")?;

    let x_hash = h(&[b"D", &h(&[b"f"]), &h(&[b"F", b"X"])]);
    let y_hash = h(&[b"D"]); // empty
    let expected = h(&[b"D", &h(&[b"x"]), &x_hash, &h(&[b"y"]), &y_hash]);

    assert_eq!(digest_all(&root)?, expected);
    Ok(())
}

/// Symlink inside a directory — verify name and content are hashed correctly.
///
/// dir/
///   sl -> points to "../nowhere"
///
/// Expected: H("D" || H("sl") || H("L" || "../nowhere"))
#[test]
#[cfg_attr(target_family = "windows", ignore)]
fn symlink_in_directory() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-symlink-in-dir")?;
    let dir = tmp.path().join("dir");
    fs::create_dir(&dir)?;
    symlink_file("../nowhere", dir.join("sl"))?;

    let expected = h(&[
        b"D",
        &h(&[b"sl"]),
        &h(&[b"L", b"../nowhere"]),
    ]);

    assert_eq!(digest_all(&dir)?, expected);
    Ok(())
}

/// Filtering out all children yields the same digest as an empty directory.
#[test]
fn filter_all_children_equals_empty_dir() -> Result<(), DigestError> {
    let tmp = TempDir::new("rd-filter-all")?;
    let dir = tmp.path().join("d");
    fs::create_dir(&dir)?;
    fs::File::create(dir.join("a"))?.write_all(b"x")?;
    fs::File::create(dir.join("b"))?.write_all(b"y")?;

    let empty = tmp.path().join("empty");
    fs::create_dir(&empty)?;

    let mut excluded = HashSet::new();
    excluded.insert(PathBuf::from("a"));
    excluded.insert(PathBuf::from("b"));
    assert_eq!(digest_excluding(&dir, excluded)?, digest_all(&empty)?);
    Ok(())
}

/// Using a different hash algorithm (Blake2b-256) works correctly.
#[test]
fn different_hash_algorithm() -> Result<(), DigestError> {
    use digest::consts::U32;
    type Blake2b256 = blake2::Blake2b<U32>;

    let tmp = TempDir::new("rd-blake2b256")?;
    let path = tmp.path().join("f");
    fs::File::create(&path)?.write_all(b"hello")?;

    let result = RecursiveDigest::<Blake2b256, _, _>::new()
        .build()
        .get_digest_of(&path)?;

    let expected = {
        let mut hasher = Blake2b256::new();
        hasher.update(b"F");
        hasher.update(b"hello");
        hasher.finalize().to_vec()
    };

    assert_eq!(result, expected);
    assert_eq!(result.len(), 32); // 256 bits
    Ok(())
}
