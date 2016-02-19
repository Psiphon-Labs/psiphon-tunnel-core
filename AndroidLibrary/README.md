##Psiphon Android Library README

###Overview

Psiphon Library for Android enables you to easily embed Psiphon in your Android
app. The Psiphon Library for Android is implemented in Go and follows the standard
conventions for using a Go library in an Android app.

###Building with Docker

Note that you may need to use `sudo docker` below, depending on your OS.

#####Create the build image:

  1. Run the command: `docker build --no-cache=true -t psiandroid .` (this may take some time to complete)
  2. Once completed, verify that you see an image named `psiandroid` when running: `docker images`

#####Run the build:

  *Ensure that the command below is run from within the `AndroidLibrary` directory*

  ```bash
  cd .. && \
    docker run \
    --rm \
    -v $(pwd):/go/src/github.com/Psiphon-Labs/psiphon-tunnel-core \
    psiandroid \
    /bin/bash -c 'source /tmp/setenv-android.sh && cd /go/src/github.com/Psiphon-Labs/psiphon-tunnel-core/AndroidLibrary && ./make.bash' \
  ; cd -
  ```
When that command completes, the compiled `.aar` file (suitable for use in an Android Studio project) will be located in the current directory (it will likely be owned by root, so be sure to `chown` to an appropriate user).

###Building without Docker (from source)

#####Prerequisites:

 - The `build-essential` package (on Debian based systems - or its equivalent for your platform)
 - Go 1.5 or later
 - Full JDK
 - Android NDK
 - Android SDK
 - OpenSSL (tested against the version [here](../openssl))
  - Follow its [README](../openssl/README.md) to prepare the environment before you follow the steps below

#####Steps:

 1. Follow Go Android documentation ([gomobile documentation](https://godoc.org/golang.org/x/mobile/cmd/gomobile))
 - Build command: `gomobile bind -target=android github.com/Psiphon-Labs/psiphon-tunnel-core/AndroidLibrary/psi`
  - Record build version info, as described [here](../README.md#setup), by passing a `-ldflags` argument to `gomobile bind`.
  - Output: `psi.aar`

###Using the Library

 1. Build `psi.aar` from via the docker container, from source, or use the [binary release](https://github.com/Psiphon-Labs/psiphon-tunnel-core/releases)
 2. Add `psi.aar` to your Android Studio project as described in the [gomobile documentation](https://godoc.org/golang.org/x/mobile/cmd/gomobile)
 3. Example usage in [TunneledWebView sample app](../SampleApps/TunneledWebView/README.md)

#####Limitations

 - Only supports one concurrent instance of Psiphon.
