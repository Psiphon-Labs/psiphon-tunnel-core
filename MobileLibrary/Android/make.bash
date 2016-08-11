#!/usr/bin/env bash

set -e

if [ ! -f make.bash ]; then
  echo "make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/Android"
  exit 1
fi

# Don't use '-u' to force updates because the docker builds always pull
# the latest versions. Outside of Docker, be aware that these dependencies
# will not be overridden w/ new versions if they already exist in $GOPATH

GOOS=arm go get -d -v github.com/Psiphon-Inc/openssl
if [ $? != 0 ]; then
  echo "..'go get -d -v github.com/psiphon-inc/openssl' failed, exiting"
  exit $?
fi
GOOS=arm go get -d -v github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon
if [ $? != 0 ]; then
  echo "..'go get -d -v github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon' failed, exiting"
  exit $?
fi

BUILDDATE=$(date --iso-8601=seconds)
BUILDREPO=$(git config --get remote.origin.url)
BUILDREV=$(git rev-parse --short HEAD)
GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')
GOMOBILEVERSION=$(gomobile version | perl -ne '/gomobile version (.*?) / && print $1')

LDFLAGS="\
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildDate=$BUILDDATE \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRepo=$BUILDREPO \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRev=$BUILDREV \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.goVersion=$GOVERSION \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.gomobileVersion=$GOMOBILEVERSION \
"

echo "Variables for ldflags:"
echo " Build date: ${BUILDDATE}"
echo " Build repo: ${BUILDREPO}"
echo " Build revision: ${BUILDREV}"
echo " Go version: ${GOVERSION}"
echo " Gomobile version: ${GOMOBILEVERSION}"
echo ""

gomobile bind -v -target=android/arm -ldflags="$LDFLAGS" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
if [ $? != 0 ]; then
  echo "..'gomobile bind' failed, exiting"
  exit $?
fi

echo "Done"
