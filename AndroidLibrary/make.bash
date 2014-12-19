#!/usr/bin/env bash

set -e

if [ ! -f make.bash ]; then
  echo 'make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/AndroidLibrary'
  exit 1
fi

ANDROID_APP=$PWD

CGO_ENABLED=1 GOOS=android GOARCH=arm GOARM=7 \
  go build -ldflags="-shared" -o libgojni.so ./libpsi

mkdir -p libs/armeabi-v7a
mv -f libgojni.so libs/armeabi-v7a/libgojni.so
