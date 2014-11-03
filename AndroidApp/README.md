Psibot README
================================================================================

Overview
--------------------------------------------------------------------------------

Psibot is a sample app that demonstrates embedding the Psiphon Go client in
an Android app. Psibot uses the Android VpnService API to route all device
traffic through tun2socks and in turn through Psiphon.

Status
--------------------------------------------------------------------------------

* Incomplete
  * Android app builds and runs but it is not yet stable.

Native libraries
--------------------------------------------------------------------------------

`app\src\main\jniLibs\<platform>\libtun2socks.so` is built from the Psiphon fork of badvpn. Source code is here: [https://bitbucket.org/psiphon/psiphon-circumvention-system/src/default/Android/badvpn/](https://bitbucket.org/psiphon/psiphon-circumvention-system/src/default/Android/badvpn/). The source was modified to change the package name to `ca.psiphon.psibot`.

Go client binary and config file
--------------------------------------------------------------------------------

`app\src\main\res\raw\psiphon_tunnel_core_arm` is built with Go targetting android/arm. At this time, android/arm support is not yet released but
is available in the development branch.

Install Go from source. The Android instructions are here:
[https://code.google.com/p/go/source/browse/README?repo=mobile](https://code.google.com/p/go/source/browse/README?repo=mobile).

In summary, download and install the Android NDK, use a script to make a standalone toolchain, and use that toolchain to build android/arm support within the Go source install. Then cross compile as usual.

In `app\src\main\res\raw\psiphon_config`, placeholders must be replaced with valid values.
