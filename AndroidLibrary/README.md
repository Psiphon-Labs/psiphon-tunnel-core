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
1. Example usage in [TunneledWebView sample app](../SampleApps/TunneledWebView/README.md)

Limitations
--------------------------------------------------------------------------------

* Only supports one concurrent instance of Psiphon.
