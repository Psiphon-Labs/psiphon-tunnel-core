#!/usr/bin/env bash

set -e -u -x

if [ ! -f make.bash ]; then
  echo "make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/ConsoleClient"
  exit 1
fi

# $2, if specified, is go build tags
if [ -z ${2+x} ]; then BUILD_TAGS=""; else BUILD_TAGS="$2"; fi

# At this time, we don't support modules
export GO111MODULE=off

EXE_BASENAME="psiphon-tunnel-core"

prepare_build () {
  BUILDINFOFILE="${EXE_BASENAME}_buildinfo.txt"
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
  echo -e "${BUILDDATE}\n${BUILDREPO}\n${BUILDREV}\n" > $BUILDINFOFILE

  echo "Variables for ldflags:"
  echo " Build date: ${BUILDDATE}"
  echo " Build repo: ${BUILDREPO}"
  echo " Build revision: ${BUILDREV}"
  echo " Go version: ${GOVERSION}"
  echo " Dependencies: ${DEPENDENCIES}"
  echo ""
}

if [ ! -d bin ]; then
  mkdir bin
fi

build_for_windows () {
  prepare_build windows

  echo "...Building windows-i686"

  CGO_LDFLAGS="-L /usr/i686-w64-mingw32/lib/ -lwsock32 -lcrypt32 -lgdi32" \
  CC=/usr/bin/i686-w64-mingw32-gcc \
  GOOS=windows GOARCH=386 go build -v -x -ldflags "$LDFLAGS" -tags "${BUILD_TAGS}" -o bin/windows/${EXE_BASENAME}-i686.exe
  RETVAL=$?
  echo ".....gox completed, exit code: $?"
  if [ $RETVAL != 0 ]; then
    echo ".....gox failed, exiting"
    exit $RETVAL
  fi
  unset RETVAL

  ## We are finding that UPXing the full Windows Psiphon client produces better results if psiphon-tunnel-core.exe is not already UPX'd.
  echo "....No UPX for this build"

  echo "...Building windows-x86_64"

  CGO_LDFLAGS="-L /usr/x86_64-w64-mingw32/lib/ -lwsock32 -lcrypt32 -lgdi32" \
  CC=/usr/bin/x86_64-w64-mingw32-gcc \
  GOOS=windows GOARCH=amd64 go build -v -x -ldflags "$LDFLAGS" -tags "${BUILD_TAGS}" -o bin/windows/${EXE_BASENAME}-x86_64.exe
  RETVAL=$?
  if [ $RETVAL != 0 ]; then
    echo ".....gox failed, exiting"
    exit $RETVAL
  fi
  unset RETVAL

  # We are finding that UPXing the full Windows Psiphon client produces better results if psiphon-tunnel-core.exe is not already UPX'd.
  echo "....No UPX for this build"
}

build_for_linux () {
  prepare_build linux

  echo "...Building linux-i686"
  # TODO: is "CFLAGS=-m32" required?
  CFLAGS=-m32 GOOS=linux GOARCH=386 go build -v -x -ldflags "$LDFLAGS" -tags "${BUILD_TAGS}" -o bin/linux/${EXE_BASENAME}-i686
  RETVAL=$?
  if [ $RETVAL != 0 ]; then
    echo ".....gox failed, exiting"
    exit $RETVAL
  fi
  unset RETVAL

  echo "....UPX packaging output"
  goupx --best bin/linux/${EXE_BASENAME}-i686
  RETVAL=$?
  if [ $RETVAL != 0 ]; then
    echo ".....goupx failed, exiting"
    exit $RETVAL
  fi
  unset RETVAL

  echo "...Building linux-x86_64"
  GOOS=linux GOARCH=amd64 go build -v -x -ldflags "$LDFLAGS" -tags "${BUILD_TAGS}" -o bin/linux/${EXE_BASENAME}-x86_64
  RETVAL=$?
  if [ $RETVAL != 0 ]; then
    echo "....gox failed, exiting"
    exit $RETVAL
  fi
  unset RETVAL

  echo "....UPX packaging output"
  goupx --best bin/linux/${EXE_BASENAME}-x86_64
  RETVAL=$?
  if [ $RETVAL != 0 ]; then
    echo ".....goupx failed, exiting"
    exit $RETVAL
  fi
  unset RETVAL
}

build_for_osx () {
  prepare_build darwin

  echo "Building darwin-x86_64..."
  echo "..Disabling CGO for this build"
  # TODO: is "CGO_ENABLED=0" required?
  CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -v -x -ldflags "$LDFLAGS" -tags "${BUILD_TAGS}" -o bin/darwin/${EXE_BASENAME}-x86_64
  # Darwin binaries don't seem to be UPXable when built this way
  echo "..No UPX for this build"
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
  osx)
    echo "..Building for OSX"
    build_for_osx
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

    build_for_osx
    if [ $? != 0 ]; then
      exit $?
    fi

    ;;
  *)
    echo "..invalid target"
    exit 1

    ;;

esac

echo "Done"
