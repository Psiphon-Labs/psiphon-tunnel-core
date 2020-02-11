## Psiphon Android Library README

### Overview

Psiphon Library for Android enables you to easily embed Psiphon in your Android
app. The Psiphon Library for Android is implemented in Go and follows the standard
conventions for using a Go library in an Android app.

### Building with Docker

Note that you may need to use `sudo docker` below, depending on your OS.

##### Create the build image:

1. While in the `MobileLibrary/Android` directory, run the command: `docker build --no-cache=true -t psiandroid .`

2. Once completed, verify that you see an image named `psiandroid` when running: `docker images`

##### Run the build:

*Ensure that the command below is run from within the `MobileLibrary/Android` directory*

```bash
cd ../.. && \
  docker run \
  --rm \
  -v $(pwd):/go/src/github.com/Psiphon-Labs/psiphon-tunnel-core \
  psiandroid \
  /bin/bash -c 'cd /go/src/github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/Android && ./make.bash' \
; cd -
```

When that command completes, the compiled `.aar` files (suitable for use in an Android Studio project) will be located in the current directory (it will likely be owned by root, so be sure to `chown` to an appropriate user).

### Building without Docker (from source)

##### Prerequisites:

 - The `build-essential` package (on Debian based systems - or its equivalent for your platform)
 - Go 1.13 or later
 - Full JDK
 - Android NDK
 - Android SDK

##### Steps:

 1. Follow Go Android documentation ([gomobile documentation](https://godoc.org/golang.org/x/mobile/cmd/gomobile))
 2. Run `make.bash`

### Using the Library

#### If building from source

 1. Build `ca.psiphon.aar` from via the docker container.
 2. Add `ca.psiphon.aar` to your Android Studio project as described in the [gomobile documentation](https://godoc.org/golang.org/x/mobile/cmd/gomobile)

#### If using Maven based binary distribution

1. Add maven repo to your app build.gradle
```
repositories {
    ...
    maven {
        url "https://raw.github.com/Psiphon-Labs/psiphon-tunnel-core-Android-library/master"
    }
}
```
then add PsiphonTunnel dependency like following
```
dependencies {
    ...
    implementation 'ca.psiphon:psiphontunnel:2.0.2'
}
```
Where 2.0.2 is the target version. Latest available release version can be found at https://github.com/Psiphon-Labs/psiphon-tunnel-core-Android-library

See example usage in [TunneledWebView sample app](./SampleApps/TunneledWebView/README.md)

---

**NOTE**

The maven repo at `https://raw.github.com/Psiphon-Labs/psiphon-tunnel-core-Android-library/master/releases` which contains releases up to v2.0.2 is deprecated and will not be updated. All new releases starting with v2.0.2 will be deployed to maven repo at  `https://raw.github.com/Psiphon-Labs/psiphon-tunnel-core-Android-library/master`

---

##### Limitations

 - Only supports one concurrent instance of Psiphon.
