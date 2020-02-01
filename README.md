# Recursive file-system digest

This library implements a simple but efficient recursive file-system digest
algorithm. You have a directory with some content in it, and you'd like
a cryptographical digest (hash) of its content.

It was created for the purpose of checksuming source code packages
in `crev`, but it is generic and can be used for any other purpose.

## Algorithm

Given any digest algorithm `H` (a Hash function algorithm),
a `RecursiveDigest(H, path)` is:

* for a file: `H("F" || file_content)`
* for a symlink: `H("S" || symlink_content)`
* for a directory: `H("D" || directory_content)`

As you can see a one-letter ASCII prefix is used to make it impossible
to create a file that has the same digest as a directory,
etc. The drawback of this approach is that `RecursiveDigest(H, path)` of
a simple file is not the same as just a normal digest of it (`H(file_content)`) .

`file_content` is just the byte content of a file.

`symlink_content` is just the path the symlink is pointing to, as bytes.

`directory_content` is created by:

* sorting all entries of a directory by name, in ascending order,
  using a simple byte-sequence comparison
* for all entries concatenating pairs of:
    * `H(entry_name)`
    * `RecursiveDigest(H, entry_path)`


