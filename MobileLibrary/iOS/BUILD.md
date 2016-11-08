# Building the Psiphon iOS Library

**Note:** If you want to use the Psiphon library, you must use the pre-built binary. See [USAGE.md](USAGE.md) for instructions. (This building doc is for Psiphon devs' reference.)

## Manual Build

### Prerequisites

* xcode `xcode-select --install`

* [git](https://git-scm.com/download/mac)

* [homebrew](http://brew.sh/)

* golang
  - `brew install go`

### Build Steps

* Run `build-psiphon-framework.sh`.
  - If this fails, especially in the `gomobile` step, try re-running it.

* The result will be in `MobileLibrary/iOS/build`.


## Automatic Build -- Jenkins

Build artifacts can be found in Jenkins.


## Deployment

* Version numbers are arbitrary, but should be [semver](http://semver.org/)-compatible.

* iOS and Android Library builds should be done at the same time, from the code, with the same version number. (There may be exceptions to this, where only one platform release makes sense.)

* Use Github Releases to publish the Library binaries. Create a tag on the correct commit hash with the name of the version. Create a Release with a zip file containing the `.framework` directory and the `USAGE.md` file. Attach the Android Library binary
