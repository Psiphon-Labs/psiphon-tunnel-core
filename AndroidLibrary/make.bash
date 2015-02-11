#!/usr/bin/env bash

set -e
#set -exv # verbose output for testing

if [ ! -f make.bash ]; then
  echo 'make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/AndroidLibrary'
  exit 1
fi

# Make sure we have our dependencies
echo -e "go-getting dependencies...\n"
go get -d -v ./...

# Force an update of the go-mobile package, since it's being improved rapidly
# NOTE: for some reason this either doesn't complete or stalls for a very long time.
#echo -e "Updating go-mobile...\n"
#go get -u -d -v golang.org/x/mobile/...

LIB_BASENAME="libgojni"
BUILDINFOFILE="${LIB_BASENAME}_buildinfo.txt"
BUILDDATE=$(date --iso-8601=seconds)
BUILDREPO=$(git config --get remote.origin.url)
BUILDREV=$(git rev-parse HEAD)
LDFLAGS="\
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildDate $BUILDDATE \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRepo $BUILDREPO \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRev $BUILDREV \
"
echo -e "${BUILDDATE}\n${BUILDREPO}\n${BUILDREV}\n" > $BUILDINFOFILE
echo -e "LDFLAGS=$LDFLAGS\n"

echo -e "Building library...\n"
CGO_ENABLED=1 GOOS=android GOARCH=arm GOARM=7 \
  go build -a -v -ldflags="-shared $LDFLAGS" -o ${LIB_BASENAME}.so ./libpsi

mkdir -p libs/armeabi-v7a
mv -f ${LIB_BASENAME}.so libs/armeabi-v7a/${LIB_BASENAME}.so

echo -e "Library can be found at: libs/armeabi-v7a/${LIB_BASENAME}.so\n"
