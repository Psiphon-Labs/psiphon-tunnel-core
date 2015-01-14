#!/usr/bin/env bash

set -e

if [ ! -f make.bash ]; then
  echo 'make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/AndroidLibrary'
  exit 1
fi

# Make sure we have our dependencies
echo 'go-getting dependencies...'
go get -d -v ./...

# Force an update of the go-mobile package, since it's being improved rapidly
# NOTE: for some reason this either doesn't complete or stalls for a very long time.
#echo 'Updating go-mobile...'
#go get -u -d -v golang.org/x/mobile/...

echo 'Building library...'
CGO_ENABLED=1 GOOS=android GOARCH=arm GOARM=7 \
  go build -a -v -ldflags="-shared" -o libgojni.so ./libpsi

mkdir -p libs/armeabi-v7a
mv -f libgojni.so libs/armeabi-v7a/libgojni.so

echo 'Library can be found at: libs/armeabi-v7a/libgojni.so'
