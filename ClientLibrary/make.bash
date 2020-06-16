#!/usr/bin/env bash

set -e -u -x

if [ ! -f make.bash ]; then
  echo "make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/ClientLibrary"
  exit 1
fi

# $2, if specified, is go build tags
if [ -z ${2+x} ]; then BUILD_TAGS=""; else BUILD_TAGS="$2"; fi

BUILD_DIR=build

if [ ! -d ${BUILD_DIR} ]; then
  mkdir ${BUILD_DIR}
fi


prepare_build () {

  BUILDDATE=$(date --iso-8601=seconds)
  BUILDREPO=$(git config --get remote.origin.url)
  BUILDREV=$(git rev-parse --short HEAD)
  GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')

  # see DEPENDENCIES comment in MobileLibrary/Android/make.bash
  DEPENDENCIES=$(echo -n "{" && GOOS=$1 go list -tags "${BUILD_TAGS}" -f '{{range $dep := .Deps}}{{printf "%s\n" $dep}}{{end}}' | GOOS=$1 xargs go list -tags "${BUILD_TAGS}" -f '{{if not .Standard}}{{.ImportPath}}{{end}}' | xargs -I pkg bash -c 'cd $GOPATH/src/$0 && if echo -n "$0" | grep -vEq "^github.com/Psiphon-Labs/psiphon-tunnel-core/" ; then echo -n "\"$0\":\"$(git rev-parse --short HEAD)\"," ; fi' pkg | sed 's/,$//' | tr -d '\n' && echo -n "}")

  LDFLAGS="\
  -s \
  -w \
  -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildDate=$BUILDDATE \
  -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRepo=$BUILDREPO \
  -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRev=$BUILDREV \
  -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.goVersion=$GOVERSION \
  -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.dependencies=$DEPENDENCIES \
  "

  echo "Variables for ldflags:"
  echo " Build date: ${BUILDDATE}"
  echo " Build repo: ${BUILDREPO}"
  echo " Build revision: ${BUILDREV}"
  echo " Go version: ${GOVERSION}"
  echo " Dependencies: ${DEPENDENCIES}"
  echo ""

}


build_for_android () {

  TARGET_OS=android
  OUTPUT_DIR="${BUILD_DIR}/${TARGET_OS}"

  prepare_build android

  TARGET_ARCH=arm
  ARMV=7

  CC="${ANDROID_NDK_TOOLCHAIN_ROOT}/${TARGET_ARCH}/bin/arm-linux-androideabi-clang" \
  CXX="${ANDROID_NDK_TOOLCHAIN_ROOT}/${TARGET_ARCH}/bin/arm-linux-androideabi-clang++" \
  GOARM=${ARMV} \
  GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH} go build -buildmode=c-shared -ldflags "$LDFLAGS" -tags "${BUILD_TAGS}" -o "${OUTPUT_DIR}/${TARGET_ARCH}${ARMV}/libpsiphontunnel.so" PsiphonTunnel.go


  TARGET_ARCH=arm64

  CC="${ANDROID_NDK_TOOLCHAIN_ROOT}/${TARGET_ARCH}/bin/aarch64-linux-android-clang" \
  CXX="${ANDROID_NDK_TOOLCHAIN_ROOT}/${TARGET_ARCH}/bin/aarch64-linux-android-clang++" \
  GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH} go build -buildmode=c-shared -ldflags "$LDFLAGS" -tags "${BUILD_TAGS}" -o "${OUTPUT_DIR}/${TARGET_ARCH}/libpsiphontunnel.so" PsiphonTunnel.go

}


build_for_linux () {

  TARGET_OS=linux
  OUTPUT_DIR="${BUILD_DIR}/${TARGET_OS}"

  prepare_build linux

  TARGET_ARCH=386
  # TODO: is "CFLAGS=-m32" required?
  CFLAGS=-m32 \
  GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH} go build -buildmode=c-shared -ldflags "$LDFLAGS" -tags "${BUILD_TAGS}" -o "${OUTPUT_DIR}/${TARGET_ARCH}/libpsiphontunnel.so" PsiphonTunnel.go


  TARGET_ARCH=amd64
  GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH} go build -buildmode=c-shared -ldflags "$LDFLAGS" -tags "${BUILD_TAGS}" -o "${OUTPUT_DIR}/${TARGET_ARCH}/libpsiphontunnel.so" PsiphonTunnel.go

}


build_for_windows () {

  TARGET_OS=windows
  OUTPUT_DIR="${BUILD_DIR}/${TARGET_OS}"

  prepare_build windows

  TARGET_ARCH=386

  CGO_ENABLED=1 \
  CGO_LDFLAGS="-static-libgcc -L /usr/i686-w64-mingw32/lib/ -lwsock32 -lcrypt32 -lgdi32" \
  CC=/usr/bin/i686-w64-mingw32-gcc \
  GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH} go build -buildmode=c-shared -ldflags "$LDFLAGS" -tags "${BUILD_TAGS}" -o "${OUTPUT_DIR}/${TARGET_ARCH}/psiphontunnel.dll" PsiphonTunnel.go


  TARGET_ARCH=amd64

  CGO_ENABLED=1 \
  CGO_LDFLAGS="-static-libgcc -L /usr/x86_64-w64-mingw32/lib/ -lwsock32 -lcrypt32 -lgdi32" \
  CC=/usr/bin/x86_64-w64-mingw32-gcc \
  GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH} go build -buildmode=c-shared -ldflags "$LDFLAGS" -tags "${BUILD_TAGS}" -o "${OUTPUT_DIR}/${TARGET_ARCH}/psiphontunnel.dll" PsiphonTunnel.go

}


build_for_ios () {

  echo "To build for iOS please use build-darwin.sh"

}


build_for_macos () {

  echo "To build for macos please use build-darwin.sh"

}


TARGET=$1
case $TARGET in
  windows)
    echo "..Building for Windows"
    build_for_windows
    exit $?

    ;;
  linux)
    echo "..Building for Linux"
    build_for_linux
    exit $?

    ;;
  macos)
    echo "..Building for MacOS"
    build_for_macos
    exit $?

    ;;
  android)
    echo "..Building for Android"
    build_for_android
    exit $?

    ;;
  ios)
    echo "..Building for iOS"
    build_for_ios
    exit $?

    ;;
  all)
    echo "..Building all"
    build_for_windows
    if [ $? != 0 ]; then
      exit $?
    fi

    build_for_linux
    if [ $? != 0 ]; then
      exit $?
    fi

    build_for_macos
    if [ $? != 0 ]; then
      exit $?
    fi

    build_for_android
    if [ $? != 0 ]; then
      exit $?
    fi

    build_for_ios
    if [ $? != 0 ]; then
      exit $?
    fi

    ;;
  *)
    echo "..invalid target"
    exit 1


    ;;

esac

echo "BUILD DONE"
