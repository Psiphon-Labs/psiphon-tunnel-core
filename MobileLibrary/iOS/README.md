# Psiphon iOS Library Meta-README

## Usage

If you are using the Library in your app, please read the [USAGE.md](USAGE.md) instructions.

## Acknowledgements

Psiphon iOS Library uses:
* [OpenSSL-for-iPhone](https://github.com/x2on/OpenSSL-for-iPhone)

### OpenSSL-for-iPhone Changes

`build-libssl.sh` rebuilds openssl on every run.  Modifications were made to
not run unless required, they are:

* Check if `libssl.a` and `libcrypto.a` are built and compare the version strings
found in files to the `VERSION` variable in `build-libssl.sh`.

* A new variable `FORCE_BUILD` is set to force a build.  Set this to *true* as
necessary.
