#!/usr/bin/env bash

set -e

if [ ! -f make.bash ]; then
  echo 'make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/AndroidApp'
  exit 1
fi

ANDROID_APP=$PWD

# Build library
(cd ../AndroidLibrary && ./make.bash)
mkdir -p app/src/main/jniLibs/armeabi-v7a && cp -f ../AndroidLibrary/libs/armeabi-v7a/libgojni.so app/src/main/jniLibs/armeabi-v7a

gradle clean build
