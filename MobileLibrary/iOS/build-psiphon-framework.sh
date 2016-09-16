#!/usr/bin/env bash
BASE_DIR=$(cd "$(dirname "$0")" ; pwd -P)
cd ${BASE_DIR}

# Ensure go is installed
which go 2>&1 > /dev/null
if [ $? -ne 0 ]; then
  echo "Go is not installed in the path, aborting"
  exit 1
fi

VALID_ARCHS="arm64 armv7 armv7s"
FRAMEWORK="Psi"
INTERMEDIATE_OUPUT_DIR="${BASE_DIR}/PsiphonTunnelController/PsiphonTunnelController"
INTERMEDIATE_OUPUT_FILE="${FRAMEWORK}.framework"
FRAMEWORK_BINARY="${INTERMEDIATE_OUPUT_DIR}/${INTERMEDIATE_OUPUT_FILE}/Versions/A/${FRAMEWORK}"

LIBSSL=${BASE_DIR}/OpenSSL-for-iPhone/lib/libssl.a
LIBCRYPTO=${BASE_DIR}/OpenSSL-for-iPhone/lib/libcrypto.a
OPENSSL_INCLUDE=${BASE_DIR}/OpenSSL-for-iPhone/include/
UMBRELLA_FRAMEWORK_XCODE_PROJECT=${BASE_DIR}/PsiphonTunnelController/PsiphonTunnelController.xcodeproj/
TRUSTED_ROOT_CA_FILE=${BASE_DIR}/PsiphonTunnelController/PsiphonTunnelController/rootCAs.txt

#Download trustedroot CAs off curl website, see https://curl.haxx.se/docs/caextract.html for details
curl -o $TRUSTED_ROOT_CA_FILE https://curl.haxx.se/ca/cacert.pem

# Not exporting this breaks go commands later if run via jenkins
export GOPATH=${PWD}/go-ios-build

GOMOBILE_PINNED_REV=e99a906c3a3ac5959fa4b8d08f90dd5f75d3b27c
GOMOBILE_PATH=${GOPATH}/src/golang.org/x/mobile/cmd/gomobile

IOS_SRC_DIR=${GOPATH}/src/github.com/Psiphon-Labs/psiphon-ios
TUNNEL_CORE_SRC_DIR=${GOPATH}/src/github.com/Psiphon-Labs/psiphon-tunnel-core
OPENSSL_SRC_DIR=${GOPATH}/src/github.com/Psiphon-Inc/openssl

PATH=${PATH}:${GOPATH}/bin

mkdir -p ${GOPATH}
mkdir -p ${INTERMEDIATE_OUPUT_DIR}

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

go get -d  -u -v github.com/Psiphon-Inc/openssl
go get -d -u -v github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi

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
    git checkout master 
    git branch -d pinned
    git checkout -b pinned ${GOMOBILE_PINNED_REV}
    go install
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
LC_ALL=C sed -i -- 's/+build android windows$/+build android windows darwin/' "${TUNNEL_CORE_SRC_DIR}/psiphon/opensslConn.go"
LC_ALL=C sed -i -- 's/+build !android,!windows$/+build !android,!windows,!darwin/' "${TUNNEL_CORE_SRC_DIR}/psiphon/opensslConn_unsupported.go"

IOS_CGO_BUILD_FLAGS='// #cgo darwin CFLAGS: -I'"${OPENSSL_INCLUDE}"'\
// #cgo darwin LDFLAGS:'"${LIBSSL}"'\
// #cgo darwin LDFLAGS:'"${LIBCRYPTO}"''

LC_ALL=C sed -i -- "s|// #cgo pkg-config: libssl|${IOS_CGO_BUILD_FLAGS}|" "${OPENSSL_SRC_DIR}/build.go"

gomobile bind  -target ios -ldflags="${LDFLAGS}" -o ${INTERMEDIATE_OUPUT_DIR}/${INTERMEDIATE_OUPUT_FILE} github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
ARCHS="$(lipo -info "${FRAMEWORK_BINARY}" | rev | cut -d ':' -f1 | rev)"
for ARCH in $ARCHS; do
  if ! [[ "${VALID_ARCHS}" == *"$ARCH"* ]]; then
    echo "Stripping ARCH ${ARCH} from ${FRAMEWORK_BINARY}"
    lipo -remove "$ARCH" -output "$FRAMEWORK_BINARY" "$FRAMEWORK_BINARY" || exit 1
  fi
done

xcodebuild clean build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO -configuration Release -sdk iphoneos -project ${UMBRELLA_FRAMEWORK_XCODE_PROJECT} CONFIGURATION_BUILD_DIR="${BASE_DIR}/build"
echo "Done."
