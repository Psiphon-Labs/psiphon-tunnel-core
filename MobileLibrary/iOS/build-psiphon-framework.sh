#!/usr/bin/env bash

set -e -u -x

if [ -z ${1+x} ]; then BUILD_TAGS=""; else BUILD_TAGS="$1"; fi

# Modify this value as we use newer Go versions.
GO_VERSION_REQUIRED="1.17.13"

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

UMBRELLA_FRAMEWORK_XCODE_PROJECT=${BASE_DIR}/PsiphonTunnel/PsiphonTunnel.xcodeproj/

# Exporting these seems necessary for subcommands to pick them up.
export GOPATH=${PWD}/go-ios-build
export PATH=${GOPATH}/bin:${PATH}

# The GOPATH we're using is temporary, so make sure there isn't one from a previous run.
rm -rf "${GOPATH}"

GOMOBILE_PINNED_REV=ce6a79cf6a13dd77095a6f8dbee5f39848fa7da1
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
# - Parameter 1: `gomobile bind` -target option value
# - Parameter 2: Variable name where gomobile output will be set to.
function gomobile_build_for_platform() {

  # Possible values are "ios" and "simulator"
  local TARGETS=$1

  echo "Build library for targets ${TARGETS}"

  local GOBIND_OUT="${BUILD_DIR}/gobind-framework/Psi.xcframework"

  # We're using a generated-code prefix to workaround https://github.com/golang/go/issues/18693
  # CGO_CFLAGS_ALLOW is to workaround https://github.com/golang/go/issues/23742 in Go 1.9.4
  CGO_CFLAGS_ALLOW="-fmodules|-fblocks" "${GOPATH}"/bin/gomobile bind -v -x \
  -target "${TARGETS}" \
  -iosversion "10.0" \
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
# Builds Psi.xcframework
#
IOS_PSI_FRAMEWORK=""
gomobile_build_for_platform "ios" IOS_PSI_FRAMEWORK

echo "$IOS_PSI_FRAMEWORK"

#
# Copies gobind output Psi.xcframework to the Xcode project
#

rm -rf "${BASE_DIR}/PsiphonTunnel/PsiphonTunnel/Psi.xcframework"
cp -r "${IOS_PSI_FRAMEWORK}" "${BASE_DIR}/PsiphonTunnel/PsiphonTunnel"

#
# Build PsiphonTunnel framework for iOS.
#

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
# Bundling the generated frameworks into a single PsiphonTunnel.xcframework
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
