#!/usr/bin/env bash

# This script takes one optional argument: 'private', if private plugins should
# be used. It should be omitted if private plugins are not desired.
if [[ $1 == "private" ]]; then
  FORCE_PRIVATE_PLUGINS=true
  echo "TRUE"
else
  FORCE_PRIVATE_PLUGINS=false
  echo "FALSE"
fi

# -x echos commands. -u exits if an unintialized variable is used.
# -e exits if a command returns an error.
set -x -u -e

# Reset the PATH to macOS default. This is mainly so we don't execute the wrong
# gomobile executable.
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/go/bin

BASE_DIR=$(cd "$(dirname "$0")" ; pwd -P)
cd ${BASE_DIR}

# The location of the final framework build
BUILD_DIR="${BASE_DIR}/build"

# Ensure go is installed
which go 2>&1 > /dev/null
if [[ $? != 0 ]]; then
  echo "Go is not installed in the path, aborting"
  exit 1
fi

VALID_IOS_ARCHS="arm64 armv7 armv7s"
VALID_SIMULATOR_ARCHS="x86_64"
FRAMEWORK="Psi"
INTERMEDIATE_OUPUT_DIR="${BASE_DIR}/PsiphonTunnel/PsiphonTunnel"
INTERMEDIATE_OUPUT_FILE="${FRAMEWORK}.framework"
FRAMEWORK_BINARY="${INTERMEDIATE_OUPUT_DIR}/${INTERMEDIATE_OUPUT_FILE}/Versions/A/${FRAMEWORK}"

PRIVATE_PLUGINS_TAG=""
if [[ ${FORCE_PRIVATE_PLUGINS} == true ]]; then PRIVATE_PLUGINS_TAG="PRIVATE_PLUGINS"; fi
BUILD_TAGS="IOS ${PRIVATE_PLUGINS_TAG}"

UMBRELLA_FRAMEWORK_XCODE_PROJECT=${BASE_DIR}/PsiphonTunnel/PsiphonTunnel.xcodeproj/

# Exporting these seems necessary for subcommands to pick them up.
export GOPATH=${PWD}/go-ios-build
export PATH=${GOPATH}/bin:${PATH}

# The GOPATH we're using is temporary, so make sure there isn't one from a previous run.
rm -rf ${GOPATH}

GOMOBILE_PINNED_REV=eb9032959f05f108b05721914dfe09cfa0c5131d
GOMOBILE_PATH=${GOPATH}/src/golang.org/x/mobile/cmd/gomobile

TUNNEL_CORE_SRC_DIR=${GOPATH}/src/github.com/Psiphon-Labs/psiphon-tunnel-core

PATH=${PATH}:${GOPATH}/bin

mkdir -p ${GOPATH}
if [[ $? != 0 ]]; then
  echo "FAILURE: mkdir -p ${GOPATH}"
  exit 1
fi

# Symlink the current source directory into GOPATH, so that we're building the
# code in this local repo, rather than pulling from Github and building that.
mkdir -p ${GOPATH}/src/github.com/Psiphon-Labs
if [[ $? != 0 ]]; then
  echo "mkdir -p ${GOPATH}/src/github.com/Psiphon-Labs"
  exit 1
fi
ln -s "${BASE_DIR}/../.." "${GOPATH}/src/github.com/Psiphon-Labs/psiphon-tunnel-core"
if [[ $? != 0 ]]; then
  echo "ln -s ../.. ${GOPATH}/src/github.com/Psiphon-Labs/psiphon-tunnel-core"
  exit 1
fi

mkdir -p ${INTERMEDIATE_OUPUT_DIR}
if [[ $? != 0 ]]; then
  echo "FAILURE: mkdir -p ${INTERMEDIATE_OUPUT_DIR}"
  exit 1
fi

# arg: binary_path
function strip_architectures() {
  valid_archs="${VALID_IOS_ARCHS} ${VALID_SIMULATOR_ARCHS}"
  ARCHS="$(lipo -info "$1" | rev | cut -d ':' -f1 | rev)"
  for ARCH in "${valid_archs}"; do
    if ! [[ "${valid_archs}" == *"$ARCH"* ]]; then
      echo "Stripping ARCH ${ARCH} from $1"
      lipo -remove "$ARCH" -output "$1" "$1"
      if [[ $? != 0 ]]; then
        echo "FAILURE: lipo $1"
        exit 1
      fi
    fi
  done
  return 0
}

# Don't use -u, because this path points to our local repo, and we don't want it overridden.
go get -d -v -tags "${BUILD_TAGS}" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
if [[ $? != 0 ]]; then
  echo "FAILURE: go get -d -v -tags "${BUILD_TAGS}" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi"
  exit 1
fi

#
# Get and install gomobile, using our pinned revision
#

go get -u golang.org/x/mobile/cmd/gomobile
cd ${GOPATH}/src/golang.org/x/mobile/cmd/gomobile
git checkout master
git checkout -b pinned ${GOMOBILE_PINNED_REV}

go install
${GOPATH}/bin/gomobile init -v -x
if [[ $? != 0 ]]; then
  echo "FAILURE: ${GOPATH}/bin/gomobile init"
  exit 1
fi

#
# gomobile bind
#

BUILDDATE=$(date +%Y-%m-%dT%H:%M:%S%z)
BUILDREPO=$(git config --get remote.origin.url)
BUILDREV=$(git rev-parse --short HEAD)
GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')
GOMOBILEVERSION=$(${GOPATH}/bin/gomobile version | perl -ne '/gomobile version (.*?) / && print $1')

# see DEPENDENCIES comment in MobileLibrary/Android/make.bash
cd ${GOPATH}/src/github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
DEPENDENCIES=$(echo -n "{" && go list -tags "${BUILD_TAGS}" -f '{{range $dep := .Deps}}{{printf "%s\n" $dep}}{{end}}' | xargs go list -f '{{if not .Standard}}{{.ImportPath}}{{end}}' | xargs -I pkg bash -c 'cd $GOPATH/src/pkg && echo -n "\"pkg\":\"$(git rev-parse --short HEAD)\","' | sed 's/,$/}/')

LDFLAGS="\
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.buildDate=${BUILDDATE} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.buildRepo=${BUILDREPO} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.buildRev=${BUILDREV} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.goVersion=${GOVERSION} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.gomobileVersion=${GOMOBILEVERSION} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.dependencies=${DEPENDENCIES} \
"

echo ""
echo "Variables for ldflags:"
echo " Build date: ${BUILDDATE}"
echo " Build repo: ${BUILDREPO}"
echo " Build revision: ${BUILDREV}"
echo " Go version: ${GOVERSION}"
echo " Gomobile version: ${GOMOBILEVERSION}"
echo ""

# We're using a generated-code prefix to workaround https://github.com/golang/go/issues/18693
${GOPATH}/bin/gomobile bind -v -x -target ios -prefix Go -tags="${BUILD_TAGS}" -ldflags="${LDFLAGS}" -o "${INTERMEDIATE_OUPUT_DIR}/${INTERMEDIATE_OUPUT_FILE}" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
rc=$?; if [[ $rc != 0 ]]; then
  echo "FAILURE: ${GOPATH}/bin/gomobile bind -target ios -tags="${BUILD_TAGS}" -ldflags="${LDFLAGS}" -o "${INTERMEDIATE_OUPUT_DIR}/${INTERMEDIATE_OUPUT_FILE}" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi"
  exit $rc
fi

strip_architectures "${FRAMEWORK_BINARY}"

#
# Do the outer framework build using Xcode
#

# Clean previous output
rm -rf "${BUILD_DIR}"
rm -rf "${BUILD_DIR}-SIMULATOR"

# Build the outer framework for phones...
xcodebuild clean build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGN_ENTITLEMENTS="" CODE_SIGNING_ALLOWED="NO" -configuration Release -sdk iphoneos ONLY_ACTIVE_ARCH=NO -project ${UMBRELLA_FRAMEWORK_XCODE_PROJECT} CONFIGURATION_BUILD_DIR="${BUILD_DIR}"
rc=$?; if [[ $rc != 0 ]]; then
  echo "FAILURE: xcodebuild iphoneos"
  exit $rc
fi

# ...and for the simulator.
xcodebuild clean build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGN_ENTITLEMENTS="" CODE_SIGNING_ALLOWED="NO" -configuration Release -sdk iphonesimulator ARCHS=x86_64 VALID_ARCHS=x86_64 ONLY_ACTIVE_ARCH=NO -project ${UMBRELLA_FRAMEWORK_XCODE_PROJECT} CONFIGURATION_BUILD_DIR="${BUILD_DIR}-SIMULATOR"
rc=$?; if [[ $rc != 0 ]]; then
  echo "FAILURE: xcodebuild iphonesimulator"
  exit $rc
fi

# Add the simulator x86_64 binary into the main framework binary.
lipo -create "${BUILD_DIR}/PsiphonTunnel.framework/PsiphonTunnel" "${BUILD_DIR}-SIMULATOR/PsiphonTunnel.framework/PsiphonTunnel" -output "${BUILD_DIR}/PsiphonTunnel.framework/PsiphonTunnel"
rc=$?; if [[ $rc != 0 ]]; then
  echo "FAILURE: lipo create"
  exit $rc
fi

# Delete the temporary simulator build files.
rm -rf "${BUILD_DIR}-SIMULATOR"

# Jenkins loses symlinks from the framework directory, which results in a build
# artifact that is invalid to use in an App Store app. Instead, we will zip the
# resulting build and use that as the artifact.
cd "${BUILD_DIR}"
zip --recurse-paths --symlinks build.zip * --exclude "*.DS_Store"

echo "BUILD DONE"
