#!/usr/bin/env bash

# build-psiphon-framework.sh builds the PsiphonTunnel.xcframework.
#
# Key steps:
# 1. Initializes a temporary Go environment and installs (vendored) `gomobile`.
# 2. Iteratively builds for different target groups (iOS/Simulator/Mac Catalyst):
#    a. Generates `Psi.xcframework` (Go bindings) using `gomobile bind` for the current group.
#    b. Copies this `Psi.xcframework` into the `PsiphonTunnel` Xcode project.
#    c. Builds the `PsiphonTunnel.framework` for the platform(s) in the current group using `xcodebuild`.
# 3. Assembles the generated `PsiphonTunnel.framework`s (for iOS, iOS Simulator, Mac Catalyst) into a single `PsiphonTunnel.xcframework`.
# 4. Creates a zip archive of the final `PsiphonTunnel.xcframework`.

set -e -u -x

if [ -z ${1+x} ]; then BUILD_TAGS=""; else BUILD_TAGS="$1"; fi

# Modify this value as we use newer Go versions.
GO_VERSION_REQUIRED="1.24.12"

# At this time, psiphon-tunnel-core doesn't support modules
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

# PsiphonTunnel Xcode project imports the framework built by gomobile,
# and defines the interface for Objective-C tunnel-core users.
UMBRELLA_FRAMEWORK_XCODE_PROJECT=${BASE_DIR}/PsiphonTunnel/PsiphonTunnel.xcodeproj/

# Exporting these seems necessary for subcommands to pick them up.
export GOPATH=${PWD}/go-ios-build
export PATH=${GOPATH}/bin:${PATH}

# The GOPATH we're using is temporary, so make sure there isn't one from a previous run.
rm -rf "${GOPATH}"

# gomobile library is vendored
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

#
# Check Go version
#

GO_VERSION=$(go version | sed -E -n 's/.*go([0-9]\.[0-9]+(\.[0-9]+)?).*/\1/p')
if [[ ${GO_VERSION} != "${GO_VERSION_REQUIRED}" ]]; then
  echo "FAILURE: go version mismatch; require ${GO_VERSION_REQUIRED}; got ${GO_VERSION}"
  exit 1
fi

#
# Copies vendored gomobile into the local GOPATH.
#

mkdir -p "${GOPATH}/src/golang.org/x"
cp -R "${GOPATH}/src/github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/go-mobile" "${GOPATH}/src/golang.org/x/mobile"
cd "${GOPATH}/src/golang.org/x/mobile/cmd/gomobile"

# Patch gomobile to edit a command that assumes modules
mv init.go init.go.orig
sed -e 's/golang.org\/x\/mobile\/cmd\/gobind@latest/golang.org\/x\/mobile\/cmd\/gobind/g' init.go.orig > init.go

go install
"${GOPATH}"/bin/gomobile init -v -x
if [[ $? != 0 ]]; then
  echo "FAILURE: ${GOPATH}/bin/gomobile init"
  exit 1
fi

# Ensure BUILD* variables reflect the tunnel-core repo
cd "${TUNNEL_CORE_SRC_DIR}"

BUILDINFOFILE="${BASE_DIR}/psiphon-tunnel-core_buildinfo.txt"
BUILDDATE=$(date +%Y-%m-%dT%H:%M:%S%z)
BUILDREPO=$(git config --get remote.origin.url)
BUILDREV=$(git rev-parse --short HEAD)
GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')

LDFLAGS="\
-s \
-w \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildDate=${BUILDDATE} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRepo=${BUILDREPO} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRev=${BUILDREV} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.goVersion=${GOVERSION} \
"

echo -e "${BUILDDATE}\n${BUILDREPO}\n${BUILDREV}\n" > "$BUILDINFOFILE"

echo ""
echo "Variables for ldflags:"
echo " Build date: ${BUILDDATE}"
echo " Build repo: ${BUILDREPO}"
echo " Build revision: ${BUILDREV}"
echo " Go version: ${GOVERSION}"
echo ""


#
# Clean previous output
#
rm -rf "${BUILD_DIR}"


# Builds the Psi.xcframework for a specific platform using gomobile.
# This function encapsulates the gomobile build command.
function gomobile_build_for_platform() {

  local gomobile_flags_str=$1
  local gobind_out="${BUILD_DIR}/gobind-framework/Psi.xcframework"

  # We're using a generated-code prefix to workaround https://github.com/golang/go/issues/18693
  # CGO_CFLAGS_ALLOW is to workaround https://github.com/golang/go/issues/23742 in Go 1.9.4

  local gomobile_cmd=(
    'CGO_CFLAGS_ALLOW="-fmodules|-fblocks" "${GOPATH}"/bin/gomobile bind -v -x'
    '-prefix Go'
    '-tags="${BUILD_TAGS}"'
    '-ldflags="${LDFLAGS}"'
    '-o "${gobind_out}"'
  )
  gomobile_cmd+=("${gomobile_flags_str}")

  # Append positional arguments last
  gomobile_cmd+=(
    'github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi'
  )

  # Execute the gomobile command
  eval "${gomobile_cmd[@]}"

  # Copy gobind output Psi.xcframework to the TunnelCore Xcode project
  rm -rf "${BASE_DIR}/PsiphonTunnel/PsiphonTunnel/Psi.xcframework"
  cp -r "${gobind_out}" "${BASE_DIR}/PsiphonTunnel/PsiphonTunnel"

  echo "${gobind_out}"
}

# Builds the project for a specific platform using xcodebuild.
function xcodebuild_for_platform() {
  local archive_name=$1
  local other_flags_str=$2

  # Build the xcodebuild command
  local xcodebuild_cmd=(
    'xcodebuild clean archive'
    '-project "${UMBRELLA_FRAMEWORK_XCODE_PROJECT}"'
    '-configuration "Release"'
    '-scheme "PsiphonTunnel"'
    '-archivePath "${BUILD_DIR}/${archive_name}"'
    'CODE_SIGN_IDENTITY=""'
    'CODE_SIGNING_REQUIRED="NO"'
    'CODE_SIGN_ENTITLEMENTS=""'
    'CODE_SIGNING_ALLOWED="NO"'
    'STRIP_BITCODE_FROM_COPIED_FILES="NO"'
    'BUILD_LIBRARY_FOR_DISTRIBUTION="YES"'
    'ONLY_ACTIVE_ARCH="NO"'
    'SKIP_INSTALL="NO"'
    'PRODUCT_NAME="PsiphonTunnel"'
  )

  # Add the platform-specific flags
  xcodebuild_cmd+=("${other_flags_str}")

  # Execute xcodebuild command
  eval "${xcodebuild_cmd[@]}"
}

#
# Build the PsiphonTunnel.framework for iOS, iOS Simulator, Mac Catalyst and macOS.
#

gomobile_build_for_platform "-target 'macos,ios,iossimulator' -iosversion '10.0'"
xcodebuild_for_platform "ios.xcarchive" " -destination 'generic/platform=iOS' EXCLUDED_ARCHS='armv7'"  # Excludes 32-bit ARM: EXCLUDED_ARCHS="armv7"
xcodebuild_for_platform "macos.xcarchive" "-sdk macosx EXCLUDED_ARCHS='i386'"

# While Network Extension doesn't work on a simulator, adding the simulator build
# allows the framework users to build and run on simulators.
xcodebuild_for_platform "iossimulator.xcarchive" "-sdk iphonesimulator EXCLUDED_ARCHS='i386'" # Excludes 32-bit Intel: EXCLUDED_ARCHS="i386"

gomobile_build_for_platform "-target 'maccatalyst' -iosversion '13.1'"
xcodebuild_for_platform "maccatalyst.xcarchive" "-destination 'generic/platform=macOS,variant=Mac Catalyst'"

#
# Bundles the generated frameworks into a single PsiphonTunnel.xcframework
#
xcodebuild -create-xcframework \
-framework "${BUILD_DIR}/ios.xcarchive/Products/Library/Frameworks/PsiphonTunnel.framework" \
-debug-symbols "${BUILD_DIR}/ios.xcarchive/dSYMs/PsiphonTunnel.framework.dSYM" \
-framework "${BUILD_DIR}/iossimulator.xcarchive/Products/Library/Frameworks/PsiphonTunnel.framework" \
-debug-symbols "${BUILD_DIR}/iossimulator.xcarchive/dSYMs/PsiphonTunnel.framework.dSYM" \
-framework "${BUILD_DIR}/maccatalyst.xcarchive/Products/Library/Frameworks/PsiphonTunnel.framework" \
-debug-symbols "${BUILD_DIR}/maccatalyst.xcarchive/dSYMs/PsiphonTunnel.framework.dSYM" \
-framework "${BUILD_DIR}/macos.xcarchive/Products/Library/Frameworks/PsiphonTunnel.framework" \
-debug-symbols "${BUILD_DIR}/macos.xcarchive/dSYMs/PsiphonTunnel.framework.dSYM" \
-output "${BUILD_DIR}/PsiphonTunnel.xcframework"

# Jenkins loses symlinks from the framework directory, which results in a build
# artifact that is invalid to use in an App Store app. Instead, we will zip the
# resulting build and use that as the artifact.
cd "${BUILD_DIR}"

zip --recurse-paths --symlinks build.zip ./PsiphonTunnel.xcframework --exclude "*.DS_Store"

echo "BUILD DONE"
