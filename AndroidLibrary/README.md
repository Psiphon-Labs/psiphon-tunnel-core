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
* [Overview README](https://code.google.com/p/go/source/browse/README?repo=mobile)
* [Sample JNI App README](https://code.google.com/p/go/source/browse/example/libhello/README?repo=mobile)
* [gobind documentation](http://godoc.org/golang.org/x/mobile/cmd/gobind)

```
/AndroidLibrary
  README.md                - this file
  libgojni.so              - build binary output
  /psi
    psi.go                 - main library source
  /go_psi
    go_psi.go              - gobind output
  /java_psi/go/psi
    Psi.java               - gobind output
  /java_golang/go
    Go.java                - fork of Go/Java integration file
    Seq.java               - fork of Go/Java integration file
  /libpsi
    main.go                - stub main package for library
```

NOTE: may change after Go 1.4 is released.

* Requires Go 1.4 or later
  * At this time, android/arm support is not yet released but.
  * Install Go from source. The Android instructions are here:
[https://code.google.com/p/go/source/browse/README?repo=mobile](https://code.google.com/p/go/source/browse/README?repo=mobile).
  * In summary, download and install the Android NDK, use a script to make a [standalone toolchain](https://developer.android.com/tools/sdk/ndk/index.html#Docs), and use that toolchain to build android/arm support within the Go source install. Then cross compile as usual.
* `$GOPATH/bin/gobind -lang=go github.com/Psiphon-Labs/psiphon-tunnel-core/AndroidLibrary/psi > go_psi/go_psi.go`
* `$GOPATH/bin/gobind -lang=java github.com/Psiphon-Labs/psiphon-tunnel-core/AndroidLibrary/psi > java_psi/go/psi/Psi.java`
* In `/libpsi` `CGO_ENABLED=1 GOOS=android GOARCH=arm GOARM=7 go build -ldflags="-shared"` and copy output file to `gojni.so`

Using
--------------------------------------------------------------------------------

1. Build from source or use the [provided shared object binary](TODO: link to release) and Java source files
1. Add Go/Java integration files `java_golang/go/*.java` to your `$src/go`
1. Add `java_psi/go/psi/Psi.java` to your `$src/go/psi`
1. Add `libgojni.so` to your Android app

NOTE: may change to Psiphon-specific library name and init.

[AndroidApp README](../AndroidApp/README.md)

See sample usage in [Psiphon.java](../AndroidApp/app/src/main/java/ca/psiphon/psibot/Psiphon.java). Uses `gobind` conventions for data passing.

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
