#!/usr/bin/env bash

set -e -x

if [ ! -f make.bash ]; then
  echo "make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/ConsoleClient"
  exit 1
fi

EXE_BASENAME="psiphon-tunnel-core"

# BUILD_TAGS needs to be outside of prepare_build because it determines what's fetched by go-get.

PRIVATE_PLUGINS_TAG="PRIVATE_PLUGINS"
BUILD_TAGS="${PRIVATE_PLUGINS_TAG}"
WINDOWS_BUILD_TAGS="${BUILD_TAGS}"
LINUX_BUILD_TAGS="${BUILD_TAGS}"
OSX_BUILD_TAGS="${BUILD_TAGS}"

prepare_build () {
  BUILDINFOFILE="${EXE_BASENAME}_buildinfo.txt"
  BUILDDATE=$(date --iso-8601=seconds)
  BUILDREPO=$(git config --get remote.origin.url)
  BUILDREV=$(git rev-parse --short HEAD)
  GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')

  # - starts the string with a `{`
  # - uses the `go list` command and passes it a template string (using the Go template syntax) saying I want all the dependencies of the package in the current directory, printing 1/line via printf
  # - pipes to `xargs` to run a command on each line output from the first command
  #  - uses `go list` with a template string to print the "Import Path" (from just below `$GOPATH/src`) if the package is not part of the standard library
  # - pipes to `xargs` again, specifiying `pkg` as the placeholder name for each item being operated on (which is the list of non standard library import paths from the previous step)
  #  - `xargs` runs a bash script (via `-c`) which changes to each import path in sequence, then echoes out `"<import path>":"<subshell output of getting the short git revision>",`
  # - this leaves a trailing `,` at the end, and no close to the JSON object, so simply `sed` replace the comma before the end of the line with `}` and you now have valid JSON
  DEPENDENCIES=$(echo -n "{" && go list -tags "$1" -f '{{range $dep := .Deps}}{{printf "%s\n" $dep}}{{end}}' | xargs go list -f '{{if not .Standard}}{{.ImportPath}}{{end}}' | xargs -I pkg bash -c 'cd $GOPATH/src/pkg && echo -n "\"pkg\":\"$(git rev-parse --short HEAD)\","' | sed 's/,$/}/')

  LDFLAGS="\
  -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.buildDate=$BUILDDATE \
  -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.buildRepo=$BUILDREPO \
  -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.buildRev=$BUILDREV \
  -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.goVersion=$GOVERSION \
  -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.dependencies=$DEPENDENCIES \
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
  echo "...Getting project dependencies (via go get) for Windows. Parameter is: '$1'"
  GOOS=windows go get -d -v -tags "$WINDOWS_BUILD_TAGS" ./...
  prepare_build "$WINDOWS_BUILD_TAGS"
  if [ $? != 0 ]; then
    echo "....'go get' failed, exiting"
    exit $?
  fi

  if [ -z $1 ] || [ "$1" == "32" ]; then
    echo "...Building windows-i686"

    CGO_LDFLAGS="-L /usr/i686-w64-mingw32/lib/ -lwsock32 -lcrypt32 -lgdi32" \
    CC=/usr/bin/i686-w64-mingw32-gcc \
    GOOS=windows GOARCH=386 go build -v -x -ldflags "$LDFLAGS" -tags "$WINDOWS_BUILD_TAGS" -o bin/windows/${EXE_BASENAME}-i686.exe
    RETVAL=$?
    echo ".....gox completed, exit code: $?"
    if [ $RETVAL != 0 ]; then
      echo ".....gox failed, exiting"
      exit $RETVAL
    fi
    unset RETVAL

    ## We are finding that UPXing the full Windows Psiphon client produces better results if psiphon-tunnel-core.exe is not already UPX'd.
    echo "....No UPX for this build"
  fi

  if [ -z $1 ] || [ "$1" == "64" ]; then
    echo "...Building windows-x86_64"

    CGO_LDFLAGS="-L /usr/x86_64-w64-mingw32/lib/ -lwsock32 -lcrypt32 -lgdi32" \
    CC=/usr/bin/x86_64-w64-mingw32-gcc \
    GOOS=windows GOARCH=amd64 go build -v -x -ldflags "$LDFLAGS" -tags "$WINDOWS_BUILD_TAGS" -o bin/windows/${EXE_BASENAME}-x86_64.exe
    RETVAL=$?
    if [ $RETVAL != 0 ]; then
      echo ".....gox failed, exiting"
      exit $RETVAL
    fi
    unset RETVAL

    # We are finding that UPXing the full Windows Psiphon client produces better results if psiphon-tunnel-core.exe is not already UPX'd.
    echo "....No UPX for this build"
  fi
}

build_for_linux () {
  echo "Getting project dependencies (via go get) for Linux. Parameter is: '$1'"
  GOOS=linux go get -d -v -tags "$LINUX_BUILD_TAGS" ./...
  prepare_build "$LINUX_BUILD_TAGS"
  if [ $? != 0 ]; then
    echo "...'go get' failed, exiting"
    exit $?
  fi

  if [ -z $1 ] || [ "$1" == "32" ]; then
    echo "...Building linux-i686"
    # TODO: is "CFLAGS=-m32" required?
    CFLAGS=-m32 GOOS=linux GOARCH=386 go build -v -x -ldflags "$LDFLAGS" -tags "$LINUX_BUILD_TAGS" -o bin/linux/${EXE_BASENAME}-i686
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
  fi

  if [ -z $1 ] || [ "$1" == "64" ]; then
    echo "...Building linux-x86_64"
    GOOS=linux GOARCH=amd64 go build -v -x -ldflags "$LDFLAGS" -tags "$LINUX_BUILD_TAGS" -o bin/linux/${EXE_BASENAME}-x86_64
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
  fi
}

build_for_osx () {
  echo "Getting project dependencies (via go get) for OSX"
  GOOS=darwin go get -d -v -tags "$OSX_BUILD_TAGS" ./...
  prepare_build "$OSX_BUILD_TAGS"
  if [ $? != 0 ]; then
    echo "..'go get' failed, exiting"
    exit $?
  fi

  echo "Building darwin-x86_64..."
  echo "..Disabling CGO for this build"
  # TODO: is "CGO_ENABLED=0" required?
  CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -v -x -ldflags "$LDFLAGS" -tags "$OSX_BUILD_TAGS" -o bin/darwin/${EXE_BASENAME}-x86_64
  # Darwin binaries don't seem to be UPXable when built this way
  echo "..No UPX for this build"
}

TARGET=$1
case $TARGET in
  windows)
    echo "..Building for Windows"
    build_for_windows $2
    exit $?

    ;;
  linux)
    echo "..Building for Linux"
    build_for_linux $2
    exit $?

    ;;
  osx)
    echo "..Building for OSX"
    build_for_osx
    exit $?

    ;;
  all)
    echo "..Building all"
    build_for_windows $2
    if [ $? != 0 ]; then
      exit $?
    fi

    build_for_linux $2
    if [ $? != 0 ]; then
      exit $?
    fi

    build_for_osx
    if [ $? != 0 ]; then
      exit $?
    fi

    ;;
  *)
    echo "..No selection made, building all"
    build_for_windows $2
    if [ $? != 0 ]; then
      exit $?
    fi

    build_for_linux $2
    if [ $? != 0 ]; then
      exit $?
    fi

    build_for_osx
    if [ $? != 0 ]; then
      exit $?
    fi

    ;;

esac

echo "Done"
