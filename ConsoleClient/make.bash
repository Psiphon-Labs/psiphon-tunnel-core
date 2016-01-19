#!/usr/bin/env bash

set -e

if [ ! -f make.bash ]; then
  echo "make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/ConsoleClient"
  exit 1
fi

EXE_BASENAME="psiphon-tunnel-core"
BUILDINFOFILE="${EXE_BASENAME}_buildinfo.txt"
BUILDDATE=$(date --iso-8601=seconds)
BUILDREPO=$(git config --get remote.origin.url)
BUILDREV=$(git rev-parse --short HEAD)

LDFLAGS="\
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildDate $BUILDDATE \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRepo $BUILDREPO \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRev $BUILDREV \
"
echo -e "${BUILDDATE}\n${BUILDREPO}\n${BUILDREV}\n" > $BUILDINFOFILE

echo "Variables for ldflags:"
echo " Build date: ${BUILDDATE}"
echo " Build repo: ${BUILDREPO}"
echo " Build revision: ${BUILDREV}"
echo ""

if [ ! -d bin ]; then
  mkdir bin
fi


prep_openssl () {
  if [ ! -f /tmp/openssl.tar.gz ]; then
    curl -L https://github.com/Psiphon-Labs/psiphon-tunnel-core/raw/master/openssl/openssl-$OPENSSL_VERSION.tar.gz -o /tmp/openssl.tar.gz
  fi

  if [ -d /tmp/openssl ]; then
    rm -rf /tmp/openssl
  fi

  mkdir -p /tmp/openssl
  tar -C /tmp/openssl -xzf /tmp/openssl.tar.gz
}

build_for_windows () {
  echo "...Getting project dependencies (via go get) for Windows. Parameter is: '$1'"
  GOOS=windows go get -d -v ./...

  if [ -z $1 ] || [ "$1" == "32" ]; then
    echo "...Building windows-i686"
    echo "....Preparing clean OpenSSL"
    prep_openssl

    cd $PKG_CONFIG_PATH && ./Configure --cross-compile-prefix=i686-w64-mingw32- mingw no-shared no-ssl2 no-ssl3 no-comp no-hw no-md2 no-md4 no-rc2 no-rc5 no-krb5 no-ripemd160 no-idea no-gost no-camellia no-seed no-3des no-heartbeats && make depend && make && cd $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/ConsoleClient || exit 1
    CGO_CFLAGS="-I $PKG_CONFIG_PATH/include/" CGO_LDFLAGS="-L $PKG_CONFIG_PATH -L /usr/i686-w64-mingw32/lib/ -lssl -lcrypto -lwsock32 -lcrypt32 -lgdi32" CC=/usr/bin/i686-w64-mingw32-gcc gox -verbose -ldflags "$LDFLAGS" -osarch windows/386 -output bin/windows/${EXE_BASENAME}-i686
    ## We are finding that UPXing the full Windows Psiphon client produces better results if psiphon-tunnel-core.exe is not already UPX'd.
    echo "....No UPX for this build"
  fi

  if [ -z $1 ] || [ "$1" == "64" ]; then
    echo "...Building windows-x86_64"
    echo "....Preparing clean OpenSSL"
    prep_openssl

    cd $PKG_CONFIG_PATH && ./Configure --cross-compile-prefix=x86_64-w64-mingw32- mingw64 no-shared no-ssl2 no-ssl3 no-comp no-hw no-md2 no-md4 no-rc2 no-rc5 no-krb5 no-ripemd160 no-idea no-gost no-camellia no-seed no-3des no-heartbeats && make depend && make && cd $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/ConsoleClient || exit 1
    CGO_CFLAGS="-I $PKG_CONFIG_PATH/include/" CGO_LDFLAGS="-L $PKG_CONFIG_PATH -L /usr/x86_64-w64-mingw32/lib/ -lssl -lcrypto -lwsock32 -lcrypt32 -lgdi32" CC=/usr/bin/x86_64-w64-mingw32-gcc gox -verbose -ldflags "$LDFLAGS" -osarch windows/amd64 -output bin/windows/${EXE_BASENAME}-x86_64
    # We are finding that UPXing the full Windows Psiphon client produces better results if psiphon-tunnel-core.exe is not already UPX'd.
    echo "....No UPX for this build"
  fi
}

build_for_linux () {
  echo "Getting project dependencies (via go get) for Linux. Parameter is: '$1'"
  GOOS=linux go get -d -v ./...

  if [ -z $1 ] || [ "$1" == "32" ]; then
    echo "...Building linux-i686"
    CFLAGS=-m32 gox -verbose -ldflags "$LDFLAGS" -osarch linux/386 -output bin/linux/${EXE_BASENAME}-i686
    echo "....UPX packaging output"
    goupx --best bin/linux/${EXE_BASENAME}-i686
  fi

  if [ -z $1 ] || [ "$1" == "64" ]; then
    echo "...Building linux-x86_64"
    gox -verbose -ldflags "$LDFLAGS" -osarch linux/amd64 -output bin/linux/${EXE_BASENAME}-x86_64
    echo "....UPX packaging output"
    goupx --best bin/linux/${EXE_BASENAME}-x86_64
  fi
}

build_for_osx () {
  echo "Getting project dependencies (via go get) for OSX"
  GOOS=darwin go get -d -v ./...

  echo "Building darwin-x86_64..."
  echo "..Disabling CGO for this build"
  CGO_ENABLED=0 gox -verbose -ldflags "$LDFLAGS" -osarch darwin/amd64 -output bin/darwin/${EXE_BASENAME}-x86_64
  # Darwin binaries don't seem to be UPXable when built this way
  echo "..No UPX for this build"
}

TARGET=$1
case $TARGET in
  windows)
    echo "..Building for Windows"
    build_for_windows $2
    ;;
  linux)
    echo "..Building for Linux"
    build_for_linux $2
    ;;
  osx)
    echo "..Building for OSX"
    build_for_osx
    ;;
  all)
    echo "..Building all"
    build_for_windows $2
    build_for_linux $2
    build_for_osx
    ;;
  *)
    echo "..No selection made, building all"
    build_for_windows $2
    build_for_linux $2
    build_for_osx
    ;;

esac

echo "Done"
