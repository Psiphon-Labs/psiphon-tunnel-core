[![Build Status](https://travis-ci.org/Psiphon-Inc/rotate-safe-writer.svg?branch=master)](https://travis-ci.org/Psiphon-Inc/rotate-safe-writer)

## Rotate Safe Writer

Makes an `io.Writer` that is resilient to `inode` changes (as caused by logrotate, file deletion, etc.)

This can be used anywhere that requires the io.Writer interface to be satisfied (including `os.File`). See the tests for usage examples

It works by storing the file's `inode` as it is opened, then checking whether or not the file at the original path still has the same `inode` value prior to calling `File.Write()`. If the `inode` has changed, the file at the original path will be re-opened, the new `inode` stored, then the write will continue as normal.
