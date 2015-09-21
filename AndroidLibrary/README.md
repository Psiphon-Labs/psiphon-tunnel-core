Psiphon Library for Android README
================================================================================

Overview
--------------------------------------------------------------------------------

Psiphon Library for Android enables you to easily embed Psiphon in your Android
app. The Psiphon Library for Android is implemented in Go and follows the standard
conventions for using a Go library in an Android app.

Status
--------------------------------------------------------------------------------

* Pre-release

Building From Source
--------------------------------------------------------------------------------

Follow Go Android documentation:
* [gomobile documentation](https://godoc.org/golang.org/x/mobile/cmd/gomobile)
* Requires Go 1.5 or later.
* Build command: `gomobile bind -target=android github.com/Psiphon-Labs/psiphon-tunnel-core/AndroidLibrary/psi`
  * Record build version info, as described [here](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/master/README.md#setup), by passing a `-ldflags` argument to `gomobile bind`.
* Output: `psi.aar`

Using
--------------------------------------------------------------------------------

1. Build `psi.aar` from source or use the [binary release](https://github.com/Psiphon-Labs/psiphon-tunnel-core/releases)
1. Add `psi.aar` to your Android Studio project as described in the [gomobile documentation](https://godoc.org/golang.org/x/mobile/cmd/gomobile)
1. Example usage in [Psibot sample app](../SampleApps/Psibot/README.md)

See sample API usage in [Psibot's PsiphonVpn.java](../SampleApps/Psibot/app/src/main/java/ca/psiphon/PsiphonVpn.java). Uses `gobind` conventions for data passing.

1. Embed a [config file](../README.md#setup)
1. Call `Go.init(getApplicationContext());` in `Application.onCreate()`
1. Extend `Psi.Listener.Stub` to receive messages in `Message(String line)`
1. Call `Psi.Start(configFile, Psi.Listener)` to start Psiphon. Catch `Exception` to receive errors.
1. Call `Psi.Stop()` to stop Psiphon.
1. Sample shows how to monitor messages and detect which proxy ports to use and when the tunnel is active.

NOTE: may add more explicit interface for state change events.

Limitations
--------------------------------------------------------------------------------

* Only supports one concurrent instance of Psiphon.
