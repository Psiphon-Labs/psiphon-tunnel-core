#!/usr/bin/env bash

# -x echos commands. -u exits if an unintialized variable is used.
# -e exits if a command returns an error.
set -x -u -e

# Reset the PATH to macOS default. This is mainly so we don't execute the wrong
# gomobile executable.
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

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

# The "OPENSSL" tag enables support of OpenSSL for use by IndistinguishableTLS.
BUILD_TAGS="OPENSSL IOS"

LIBSSL=${BASE_DIR}/OpenSSL-for-iPhone/lib/libssl.a
LIBCRYPTO=${BASE_DIR}/OpenSSL-for-iPhone/lib/libcrypto.a
OPENSSL_INCLUDE=${BASE_DIR}/OpenSSL-for-iPhone/include/
UMBRELLA_FRAMEWORK_XCODE_PROJECT=${BASE_DIR}/PsiphonTunnel/PsiphonTunnel.xcodeproj/
TRUSTED_ROOT_CA_FILE=${BASE_DIR}/PsiphonTunnel/PsiphonTunnel/rootCAs.txt

# Download trustedroot CAs off curl website, see https://curl.haxx.se/docs/caextract.html for details
curl -o $TRUSTED_ROOT_CA_FILE https://curl.haxx.se/ca/cacert.pem

if [[ $? != 0 ]]; then
  echo "FAILURE: curl -o $TRUSTED_ROOT_CA_FILE https://curl.haxx.se/ca/cacert.pem"
  exit 1
fi

# Exporting these seems necessary for subcommands to pick them up.
export GOPATH=${PWD}/go-ios-build
export PATH=${GOPATH}/bin:${PATH}

# The GOPATH we're using is temporary, so make sure there isn't one from a previous run.
rm -rf ${GOPATH}

# When updating the pinned rev, you will have to manually delete go-ios-build
GOMOBILE_PINNED_REV=72eef9d09307f0b437153fd152229f56edc0ab20
GOMOBILE_PATH=${GOPATH}/src/golang.org/x/mobile/cmd/gomobile

IOS_SRC_DIR=${GOPATH}/src/github.com/Psiphon-Labs/psiphon-ios
TUNNEL_CORE_SRC_DIR=${GOPATH}/src/github.com/Psiphon-Labs/psiphon-tunnel-core
OPENSSL_SRC_DIR=${GOPATH}/src/github.com/Psiphon-Inc/openssl

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

if [ ! -e ${IOS_SRC_DIR} ]; then
  echo "iOS source directory (${IOS_SRC_DIR}) not found, creating link"
  mkdir -p $(dirname ${IOS_SRC_DIR})
  ln -s $(pwd -P) $IOS_SRC_DIR
  if [[ $? != 0 ]]; then
    echo "..Could not create symlink, aborting"
    exit 1
  fi
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

cd OpenSSL-for-iPhone && ./build-libssl.sh; cd -

strip_architectures "${LIBSSL}"
strip_architectures "${LIBCRYPTO}"

go get -d -u -v -tags "${BUILD_TAGS}" github.com/Psiphon-Inc/openssl
if [[ $? != 0 ]]; then
  echo "FAILURE: go get -d -u -v -tags "${BUILD_TAGS}" github.com/Psiphon-Inc/openssl"
  exit 1
fi

# Don't use -u, because this path points to our local repo, and we don't want it overridden.
go get -d -v -tags "${BUILD_TAGS}" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
if [[ $? != 0 ]]; then
  echo "FAILURE: go get -d -v -tags "${BUILD_TAGS}" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi"
  exit 1
fi

function check_pinned_version() {
  echo "Checking for gomobile revision: '${GOMOBILE_PINNED_REV}'"
  if [ -e ${GOMOBILE_PATH} ]; then
    echo "..Gomobile path found"
    cd ${GOMOBILE_PATH}
    CURRENT_REVISION=$(git rev-parse HEAD)
    if [ ${CURRENT_REVISION} != ${GOMOBILE_PINNED_REV} ]; then
      echo "..Current revision '${CURRENT_REVISION}' does not match"
      return 1
    else
      echo "..Current revision matches"
      return 0
    fi
  else
    echo "Could not find GOMOBILE_PATH (${GOMOBILE_PATH})"
    return 1
  fi
}

set +e
check_pinned_version
rc=$?
set -e
if [[ $rc != 0 ]]; then
    go get -u golang.org/x/mobile/cmd/gomobile
    cd ${GOPATH}/src/golang.org/x/mobile/cmd/gomobile
    git checkout master
    git checkout -b pinned ${GOMOBILE_PINNED_REV}
    go install
    ${GOPATH}/bin/gomobile init -v
    if [[ $? != 0 ]]; then
      echo "FAILURE: ${GOPATH}/bin/gomobile init -v"
      exit 1
    fi
    check_pinned_version
    if [[ $? != 0 ]]; then
      echo "gomobile not found, aborting"
      exit 1
    fi
fi

BUILDDATE=$(date +%Y-%m-%dT%H:%M:%S%z)
BUILDREPO=$(git config --get remote.origin.url)
BUILDREV=$(git rev-parse --short HEAD)
GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')
GOMOBILEVERSION=$(${GOPATH}/bin/gomobile version | perl -ne '/gomobile version (.*?) / && print $1')

LDFLAGS="\
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.buildDate=${BUILDDATE} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.buildRepo=${BUILDREPO} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.buildRev=${BUILDREV} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.goVersion=${GOVERSION} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.gomobileVersion=${GOMOBILEVERSION} \
"

echo ""
echo "Variables for ldflags:"
echo " Build date: ${BUILDDATE}"
echo " Build repo: ${BUILDREPO}"
echo " Build revision: ${BUILDREV}"
echo " Go version: ${GOVERSION}"
echo " Gomobile version: ${GOMOBILEVERSION}"
echo ""

# Patch source files to build on Darwin
IOS_CGO_BUILD_FLAGS='// #cgo darwin CFLAGS: -I'"${OPENSSL_INCLUDE}"'\
// #cgo darwin LDFLAGS:'"${LIBSSL}"'\
// #cgo darwin LDFLAGS:'"${LIBCRYPTO}"''

LC_ALL=C sed -i -- "s|// #cgo pkg-config: libssl|${IOS_CGO_BUILD_FLAGS}|" "${OPENSSL_SRC_DIR}/build.go"

${GOPATH}/bin/gomobile bind -v -x -target ios -tags "${BUILD_TAGS}" -ldflags="${LDFLAGS}" -o "${INTERMEDIATE_OUPUT_DIR}/${INTERMEDIATE_OUPUT_FILE}" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
rc=$?; if [[ $rc != 0 ]]; then
  echo "FAILURE: ${GOPATH}/bin/gomobile bind -target ios -ldflags="${LDFLAGS}" -o "${INTERMEDIATE_OUPUT_DIR}/${INTERMEDIATE_OUPUT_FILE}" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi"
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
xcodebuild clean build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO -configuration Release -sdk iphoneos ONLY_ACTIVE_ARCH=NO -project ${UMBRELLA_FRAMEWORK_XCODE_PROJECT} CONFIGURATION_BUILD_DIR="${BUILD_DIR}"
rc=$?; if [[ $rc != 0 ]]; then
  echo "FAILURE: xcodebuild iphoneos"
  exit $rc
fi

# ...and for the simulator.
xcodebuild clean build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO -configuration Release -sdk iphonesimulator ARCHS=x86_64 VALID_ARCHS=x86_64 ONLY_ACTIVE_ARCH=NO -project ${UMBRELLA_FRAMEWORK_XCODE_PROJECT} CONFIGURATION_BUILD_DIR="${BUILD_DIR}-SIMULATOR"
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

echo "BUILD DONE"
