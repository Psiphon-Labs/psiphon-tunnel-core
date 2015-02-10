#!/usr/bin/env bash

set -e
#set -xv # verbose output for testing

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

LDFLAGS="\
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildDate `date --iso-8601=seconds` \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRepo `git config --get remote.origin.url` \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRev `git rev-parse HEAD` \
"
echo -e "LDFLAGS=$LDFLAGS\n"

echo -e "Building library...\n"
CGO_ENABLED=1 GOOS=android GOARCH=arm GOARM=7 \
  go build -a -v -ldflags="-shared $LDFLAGS" -o libgojni.so ./libpsi

mkdir -p libs/armeabi-v7a
mv -f libgojni.so libs/armeabi-v7a/libgojni.so

echo -e "Library can be found at: libs/armeabi-v7a/libgojni.so\n"
