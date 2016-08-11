##Psiphon iOS Library README

###Overview

Psiphon Library for iOS enables you to easily embed Psiphon in your iOS
app. The Psiphon Library for iOS is implemented in Go and follows the standard
conventions for using a Go library in an iOS app.

###Building

####Prerequisites

* xcode `xcode-select --install`
* [git](https://git-scm.com/download/mac)
* homebrew
  * Install from terminal: `/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"`
* golang 
  * Install from terminal: `brew install go`

####Build Steps

* run `build-psiphon-framework.sh`

###Using the Library and Sample Apps

Coming soon

###Acknowledgements

Psiphon iOS Library uses:
* [OpenSSL-for-iPhone](https://github.com/x2on/OpenSSL-for-iPhone)

####OpenSSL-for-iPhone Changes

`build-libssl.sh` rebuilds openssl on every run.  Modifications were made to 
not run unless required, they are:

* Check if `libssl.a` and `libcrypto.a` are built and compare the version strings
found in files to the `VERSION` variable in `build-libssl.sh`.

* A new variable `FORCE_BUILD` is set to force a build.  Set this to *true* as 
necessary.
