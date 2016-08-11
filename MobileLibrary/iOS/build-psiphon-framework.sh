#!/usr/bin/env bash

BASE_DIR=$(cd "$(dirname "$0")" ; pwd -P)
cd ${BASE_DIR}

# Ensure go is installed
which go 2>&1 > /dev/null
if [ $? -ne 0 ]; then
  echo "Go is not installed in the path, aborting"
  exit 1
fi

OUTPUT_DIR=${BASE_DIR}/framework
OUTPUT_FILE=Psi.framework

LIBSSL=${BASE_DIR}/OpenSSL-for-iPhone/lib/libssl.a
LIBCRYPTO=${BASE_DIR}/OpenSSL-for-iPhone/lib/libcrypto.a
OPENSSL_INCLUDE=${BASE_DIR}/OpenSSL-for-iPhone/include/

# Not exporting this breaks go commands later if run via jenkins
export GOPATH=${PWD}/go-ios-build

GOMOBILE_PINNED_REV=8ab5dbbea1dc4713a98b6f1d51de4582a43e3fa8
GOMOBILE_PATH=${GOPATH}/src/golang.org/x/mobile/cmd/gomobile

IOS_SRC_DIR=${GOPATH}/src/github.com/Psiphon-Labs/psiphon-ios
TUNNEL_CORE_SRC_DIR=${GOPATH}/src/github.com/Psiphon-Labs/psiphon-tunnel-core
OPENSSL_SRC_DIR=${GOPATH}/src/github.com/Psiphon-Inc/openssl

PATH=${PATH}:${GOPATH}/bin

mkdir -p ${GOPATH}
mkdir -p ${OUTPUT_DIR}

if [ ! -e ${IOS_SRC_DIR} ]; then
  echo "iOS source directory (${IOS_SRC_DIR}) not found, creating link"
  mkdir -p $(dirname ${IOS_SRC_DIR})
  ln -s $(pwd -P) $IOS_SRC_DIR
  if [ $? -ne 0 ]; then
    echo "..Could not create symlink, aborting"
    exit 1
  fi
fi

cd OpenSSL-for-iPhone && ./build-libssl.sh; cd -

go get -d -v github.com/Psiphon-Inc/openssl
go get -d -v github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi

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

check_pinned_version
if [ $? -ne 0 ]; then
    go get -u golang.org/x/mobile/cmd/gomobile
    cd ${GOPATH}/src/golang.org/x/mobile/cmd/gomobile
    git checkout -b pinned ${GOMOBILE_PINNED_REV}
    go build
    gomobile init -v
    check_pinned_version
    if [ $? -ne 0 ]; then
      echo "gomobile not found, aborting"
      exit 1
    fi
fi

BUILDDATE=$(date +%Y-%m-%dT%H:%M:%S%z)
BUILDREPO=$(git config --get remote.origin.url)
BUILDREV=$(git rev-parse --short HEAD)
GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')
GOMOBILEVERSION=$(gomobile version | perl -ne '/gomobile version (.*?) / && print $1')

LDFLAGS="\
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildDate=${BUILDDATE} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRepo=${BUILDREPO} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRev=${BUILDREV} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.goVersion=${GOVERSION} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.gomobileVersion=${GOMOBILEVERSION} \
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
LC_ALL=C sed -i -- 's/+build android windows$/+build android windows darwin/' "${TUNNEL_CORE_SRC_DIR}/psiphon/opensslConn.go"
LC_ALL=C sed -i -- 's/+build !android,!windows$/+build !android,!windows,!darwin/' "${TUNNEL_CORE_SRC_DIR}/psiphon/opensslConn_unsupported.go"

IOS_CGO_BUILD_FLAGS='// #cgo darwin CFLAGS: -I'"${OPENSSL_INCLUDE}"'\
// #cgo darwin LDFLAGS:'"${LIBSSL}"'\
// #cgo darwin LDFLAGS:'"${LIBCRYPTO}"''

LC_ALL=C sed -i -- "s|// #cgo pkg-config: libssl|${IOS_CGO_BUILD_FLAGS}|" "${OPENSSL_SRC_DIR}/build.go"

gomobile bind -v -target ios -ldflags="${LDFLAGS}" -o ${OUTPUT_DIR}/${OUTPUT_FILE} github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
