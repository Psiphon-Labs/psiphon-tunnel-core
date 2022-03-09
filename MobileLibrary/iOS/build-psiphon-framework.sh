#!/usr/bin/env bash

set -e -u -x

if [ -z ${1+x} ]; then BUILD_TAGS=""; else BUILD_TAGS="$1"; fi

# Modify this value as we use newer Go versions.
GO_VERSION_REQUIRED="1.17.8"

# At this time, gomobile doesn't support modules
export GO111MODULE=off

# Reset the PATH to macOS default. This is mainly so we don't execute the wrong
# gomobile executable.
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/go/bin

# $GOROOT/bin allows build automation to provide various Go versions dynamically.
# As gomobile would be installed at $GOPATH/bin, there is minimal risk that
# adding $GOROOT/bin will run an unexpected gomobile binary.
PATH=$GOROOT/bin:$PATH

BASE_DIR=$(cd "$(dirname "$0")" ; pwd -P)
cd "${BASE_DIR}"

# The location of the final framework build
BUILD_DIR="${BASE_DIR}/build"

# Ensure go is installed
which go 2>&1 > /dev/null
if [[ $? != 0 ]]; then
  echo "Go is not installed in the path, aborting"
  exit 1
fi

UMBRELLA_FRAMEWORK_XCODE_PROJECT=${BASE_DIR}/PsiphonTunnel/PsiphonTunnel.xcodeproj/

# Exporting these seems necessary for subcommands to pick them up.
export GOPATH=${PWD}/go-ios-build
export PATH=${GOPATH}/bin:${PATH}

# The GOPATH we're using is temporary, so make sure there isn't one from a previous run.
rm -rf "${GOPATH}"

GOMOBILE_PINNED_REV=92f3b9caf7ba8f4f9c10074225afcba0cba47a62
GOMOBILE_PATH=${GOPATH}/src/golang.org/x/mobile/cmd/gomobile

TUNNEL_CORE_SRC_DIR=${GOPATH}/src/github.com/Psiphon-Labs/psiphon-tunnel-core

PATH=${PATH}:${GOPATH}/bin

mkdir -p "${GOPATH}"
if [[ $? != 0 ]]; then
  echo "FAILURE: mkdir -p ${GOPATH}"
  exit 1
fi

# Symlink the current source directory into GOPATH, so that we're building the
# code in this local repo, rather than pulling from Github and building that.
mkdir -p "${GOPATH}/src/github.com/Psiphon-Labs"
if [[ $? != 0 ]]; then
  echo "mkdir -p ${GOPATH}/src/github.com/Psiphon-Labs"
  exit 1
fi
ln -s "${BASE_DIR}/../.." "${GOPATH}/src/github.com/Psiphon-Labs/psiphon-tunnel-core"
if [[ $? != 0 ]]; then
  echo "ln -s ../.. ${GOPATH}/src/github.com/Psiphon-Labs/psiphon-tunnel-core"
  exit 1
fi

# Builds Psi.framework library for the given platform.
#
# - Parameter 1: Possible values are "ios" and "simulator"
# - Parameter 2: Variable name to set output path to.
function gomobile_build_for_platform() {

  # Possible values are "ios" and "simulator"
  local PLATFORM=$1

  local TARGETS=""

  # gomobile pinned version 92f3b9c list of
  # valid archs are "arm", "arm64", "386", "amd64".
  # https://github.com/golang/mobile/blob/92f3b9caf7ba8f4f9c10074225afcba0cba47a62/cmd/gomobile/env.go#L26
  #
  # As of Go 1.15, "ios/arm" is no longer supported: https://golang.org/doc/go1.15#darwin
  case "${PLATFORM}" in
    ios)
      TARGETS="ios/arm64"
      ;;
    simulator)
      TARGETS="ios/amd64"
      ;;
    *)
      echo "FATAL ERROR: Unknown platform ${PLATFORM}"
      exit 1
      ;;
  esac

  echo "Build library for platform ${PLATFORM}"

  local FRAMEWORK="Psi"

  # Since frameworks for all platforms share the same name "Psi.framework",
  # each framework should be in its own directory.
  local INTERMEDIATE_OUPUT_DIR="${BUILD_DIR}/${PLATFORM}-psi-framework"

  local INTERMEDIATE_OUPUT_FILE="${FRAMEWORK}.framework"
  # local FRAMEWORK_BINARY="${INTERMEDIATE_OUPUT_DIR}/${INTERMEDIATE_OUPUT_FILE}/Versions/A/${FRAMEWORK}"

  local GOBIND_OUT="${INTERMEDIATE_OUPUT_DIR}/${INTERMEDIATE_OUPUT_FILE}"

  # We're using a generated-code prefix to workaround https://github.com/golang/go/issues/18693
  # CGO_CFLAGS_ALLOW is to workaround https://github.com/golang/go/issues/23742 in Go 1.9.4
  CGO_CFLAGS_ALLOW="-fmodules|-fblocks" "${GOPATH}"/bin/gomobile bind -v -x \
  -target "${TARGETS}" \
  -prefix Go \
  -tags="${BUILD_TAGS}" \
  -ldflags="${LDFLAGS}" \
  -o "${GOBIND_OUT}" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi

  rc=$?; if [[ $rc != 0 ]]; then
    echo "FAILURE: gomobile bind failed".
    exit $rc
  fi


  # Sets parameter $2 to value of GOBIND_OUT.
  eval "$2=${GOBIND_OUT}"
}

#
# Check Go version
#

GO_VERSION=$(go version | sed -E -n 's/.*go([0-9]\.[0-9]+(\.[0-9]+)?).*/\1/p')
if [[ ${GO_VERSION} != "${GO_VERSION_REQUIRED}" ]]; then
  echo "FAILURE: go version mismatch; require ${GO_VERSION_REQUIRED}; got ${GO_VERSION}"
  exit 1
fi

#
# Get and install gomobile, using our pinned revision
#

go get -u golang.org/x/mobile/cmd/gomobile
cd "${GOPATH}"/src/golang.org/x/mobile/cmd/gomobile
git checkout master
git checkout -b pinned ${GOMOBILE_PINNED_REV}

go install
"${GOPATH}"/bin/gomobile init -v -x
if [[ $? != 0 ]]; then
  echo "FAILURE: ${GOPATH}/bin/gomobile init"
  exit 1
fi

#
# gomobile bind
#

# Ensure BUILD* variables reflect the tunnel-core repo
cd "${TUNNEL_CORE_SRC_DIR}"

BUILDINFOFILE="${BASE_DIR}/psiphon-tunnel-core_buildinfo.txt"
BUILDDATE=$(date +%Y-%m-%dT%H:%M:%S%z)
BUILDREPO=$(git config --get remote.origin.url)
BUILDREV=$(git rev-parse --short HEAD)
GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')
GOMOBILEVERSION=$("${GOPATH}"/bin/gomobile version | perl -ne '/gomobile version (.*?) / && print $1')

# see DEPENDENCIES comment in MobileLibrary/Android/make.bash
cd "${GOPATH}"/src/github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
DEPENDENCIES=$(echo -n "{" && GOOS=darwin go list -tags "${BUILD_TAGS}" -f '{{range $dep := .Deps}}{{printf "%s\n" $dep}}{{end}}' | GOOS=darwin xargs go list -tags "${BUILD_TAGS}" -f '{{if not .Standard}}{{.ImportPath}}{{end}}' | xargs -I pkg bash -c 'cd $GOPATH/src/$0 && if echo -n "$0" | grep -vEq "^github.com/Psiphon-Labs/psiphon-tunnel-core/" ; then echo -n "\"$0\":\"$(git rev-parse --short HEAD)\"," ; fi' pkg | sed 's/,$//' | tr -d '\n' && echo -n "}")

LDFLAGS="\
-s \
-w \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildDate=${BUILDDATE} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRepo=${BUILDREPO} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRev=${BUILDREV} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.goVersion=${GOVERSION} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.gomobileVersion=${GOMOBILEVERSION} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.dependencies=${DEPENDENCIES} \
"

echo -e "${BUILDDATE}\n${BUILDREPO}\n${BUILDREV}\n" > "$BUILDINFOFILE"

echo ""
echo "Variables for ldflags:"
echo " Build date: ${BUILDDATE}"
echo " Build repo: ${BUILDREPO}"
echo " Build revision: ${BUILDREV}"
echo " Go version: ${GOVERSION}"
echo " Gomobile version: ${GOMOBILEVERSION}"
echo ""


#
# Clean previous output
#
rm -rf "${BUILD_DIR}"


#
# Builds Psi.framework for each platform/variant.
#
IOS_PSI_FRAMEWORK=""
gomobile_build_for_platform "ios" IOS_PSI_FRAMEWORK

SIMULATOR_PSI_FRAMEWORK=""
gomobile_build_for_platform "simulator" SIMULATOR_PSI_FRAMEWORK


#
# Xcode archive for each platform.
#

# Xcode project requires Psi.framework bundle at $PSI_FRAMEWORK.
# Except for macOS, Apple does not support umbrella frameworks that
# contain other frameworks. So for building framework for each platform/variant,
# the Psi.framework should be copied to the path at $PSI_FRAMEWORK_PATH.
PSI_FRAMEWORK_PATH="${BASE_DIR}/PsiphonTunnel/PsiphonTunnel"
PSI_FRAMEWORK="${PSI_FRAMEWORK_PATH}/Psi.framework"


# Build PsiphonTunnel framework for iOS.
echo "$IOS_PSI_FRAMEWORK"
echo "$SIMULATOR_PSI_FRAMEWORK"

# Copies iOS Psi.framework 
rm -rf "${PSI_FRAMEWORK}"
cp -r "${IOS_PSI_FRAMEWORK}" "${PSI_FRAMEWORK_PATH}"

IOS_ARCHIVE="${BUILD_DIR}/ios.xcarchive"

xcodebuild clean archive \
-project "${UMBRELLA_FRAMEWORK_XCODE_PROJECT}" \
-scheme "PsiphonTunnel" \
-configuration "Release" \
-sdk iphoneos \
-archivePath "${IOS_ARCHIVE}" \
CODE_SIGN_IDENTITY="" \
CODE_SIGNING_REQUIRED="NO" \
CODE_SIGN_ENTITLEMENTS="" \
CODE_SIGNING_ALLOWED="NO" \
STRIP_BITCODE_FROM_COPIED_FILES="NO" \
BUILD_LIBRARY_FOR_DISTRIBUTION="YES" \
ONLY_ACTIVE_ARCH="NO" \
SKIP_INSTALL="NO" \
EXCLUDED_ARCHS="armv7"

# Build PsiphonTunnel framework for simulator.
#
# Note:
# - Excludes 32-bit Intel: EXCLUDED_ARCHS="i386".
# - Excludes ARM Macs: EXCLUDED_ARCHS="arm64".

# Copies simulator Psi.framework 
rm -rf "${PSI_FRAMEWORK}"
cp -r "${SIMULATOR_PSI_FRAMEWORK}" "${PSI_FRAMEWORK_PATH}"

SIMULATOR_ARCHIVE="${BUILD_DIR}/simulator.xcarchive"

xcodebuild clean archive \
-project "${UMBRELLA_FRAMEWORK_XCODE_PROJECT}" \
-scheme "PsiphonTunnel" \
-configuration "Release" \
-sdk iphonesimulator \
-archivePath "${SIMULATOR_ARCHIVE}" \
CODE_SIGN_IDENTITY="" \
CODE_SIGNING_REQUIRED="NO" \
CODE_SIGN_ENTITLEMENTS="" \
CODE_SIGNING_ALLOWED="NO" \
STRIP_BITCODE_FROM_COPIED_FILES="NO" \
BUILD_LIBRARY_FOR_DISTRIBUTION="YES" \
ONLY_ACTIVE_ARCH="NO" \
SKIP_INSTALL="NO" \
EXCLUDED_ARCHS="arm64 i386"

#
# Building PsiphonTunnel.xcframework
#

xcodebuild -create-xcframework \
-framework "${IOS_ARCHIVE}/Products/Library/Frameworks/PsiphonTunnel.framework" \
-debug-symbols "${IOS_ARCHIVE}/dSYMs/PsiphonTunnel.framework.dSYM" \
-framework "${SIMULATOR_ARCHIVE}/Products/Library/Frameworks/PsiphonTunnel.framework" \
-debug-symbols "${SIMULATOR_ARCHIVE}/dSYMs/PsiphonTunnel.framework.dSYM" \
-output "${BUILD_DIR}/PsiphonTunnel.xcframework"


# Jenkins loses symlinks from the framework directory, which results in a build
# artifact that is invalid to use in an App Store app. Instead, we will zip the
# resulting build and use that as the artifact.
cd "${BUILD_DIR}"

zip --recurse-paths --symlinks build.zip ./PsiphonTunnel.xcframework --exclude "*.DS_Store"

echo "BUILD DONE"
