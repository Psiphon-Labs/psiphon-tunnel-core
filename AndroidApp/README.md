Psibot README
================================================================================

Overview
--------------------------------------------------------------------------------

Psibot is a sample app that demonstrates embedding the Psiphon Go client in
an Android app. Psibot uses the Android VpnService API to route all device
traffic through tun2socks and in turn through Psiphon.

Status
--------------------------------------------------------------------------------

* Pre-release

Native libraries
--------------------------------------------------------------------------------

`app\src\main\jniLibs\<platform>\libtun2socks.so` is built from the Psiphon fork of badvpn. Source code is here: [https://bitbucket.org/psiphon/psiphon-circumvention-system/src/default/Android/badvpn/](https://bitbucket.org/psiphon/psiphon-circumvention-system/src/default/Android/badvpn/). The source was modified to change the package name to `ca.psiphon.psibot`.

Psiphon Android Library and config file
--------------------------------------------------------------------------------

Uses the [Psiphon Android Library](../AndroidLibrary/README.md).

In `app\src\main\res\raw\psiphon_config`, placeholders must be replaced with valid values.
