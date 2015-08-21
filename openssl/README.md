Psiphon OpenSSL README
================================================================================

Overview
--------------------------------------------------------------------------------

Psiphon Tunnel Core may be configured to use OpenSSL, in place of Go's TLS, when
it is advantageous to emulate more common TLS implementations. This facility is
used as a circumvention measure to ensure Psiphon client TLS ClientHello messages
mimic common TLS ClientHellos from, e.g., stock Android app SSLSocket connections
vs. the more distinguishable (blockable) Go TLS ClientHello.

This directory contains source and scripts to build OpenSSL libraries that can be
statically linked with Psiphon Tunnel Core.

Mimicking stock TLS implementations is done both at compile time (no-heartbeats)
and at [runtime](psiphon/opensslConn.go) (specific cipher suites and options).

Android
--------------------------------------------------------------------------------

Ensure `ANDROID_NDK_ROOT` is set. Run the `build-android.sh` script to build
static libraries for Android.

When running `gomobile bind` to build the Android library, set `CGO` environment
variables as follows (alternatively, set up `pkg-config`, which is used by the
[openssl package](https://github.com/Psiphon-Inc/openssl/blob/master/build.go)).

```
export CGO_CFLAGS="-I<path>/include"
export CGO_LDFLAGS="-L<path> -lssl -lcrypto"
```
