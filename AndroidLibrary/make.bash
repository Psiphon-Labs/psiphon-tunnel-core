#!/usr/bin/env bash

set -e

if [ ! -f make.bash ]; then
  echo "make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/AndroidLibrary"
  exit 1
fi

GOOS=arm go get -d -v github.com/Psiphon-Inc/openssl
GOOS=arm go get -d -v ./...
if [ $? != 0 ]; then
  echo "..'go get' failed, exiting"
  exit $?
fi

BUILDDATE=$(date --iso-8601=seconds)
BUILDREPO=$(git config --get remote.origin.url)
BUILDREV=$(git rev-parse --short HEAD)

LDFLAGS="\
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildDate=$BUILDDATE \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRepo=$BUILDREPO \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRev=$BUILDREV \
"

echo "Variables for ldflags:"
echo " Build date: ${BUILDDATE}"
echo " Build repo: ${BUILDREPO}"
echo " Build revision: ${BUILDREV}"
echo ""

gomobile bind -v -ldflags="$LDFLAGS" github.com/Psiphon-Labs/psiphon-tunnel-core/AndroidLibrary/psi
if [ $? != 0 ]; then
  echo "..'gomobile bind' failed, exiting"
  exit $?
fi

echo "Done"
