#!/usr/bin/env bash

set -e -u -x

BASE_DIR=$( cd "$(dirname "$0")" ; pwd -P )
cd $BASE_DIR

if [ ! -f make.bash ]; then
  echo "make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/Server"
  exit 1
fi

# $1, if specified, is go build tags
if [ -z ${1+x} ]; then BUILD_TAGS=""; else BUILD_TAGS="$1"; fi

# At this time, we don't support modules
export GO111MODULE=off

prepare_build () {
  BUILDINFOFILE="psiphond_buildinfo.txt"
  BUILDDATE=$(date -Iseconds)
  BUILDREPO=$(git config --get remote.origin.url)
  BUILDREV=$(git rev-parse --short HEAD)
  GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')

  # see DEPENDENCIES comment in MobileLibrary/Android/make.bash
  DEPENDENCIES=$(echo -n "{" && GOOS=$1 go list -tags "${BUILD_TAGS}" -f '{{range $dep := .Deps}}{{printf "%s\n" $dep}}{{end}}' | GOOS=$1 xargs go list -tags "${BUILD_TAGS}" -f '{{if not .Standard}}{{.ImportPath}}{{end}}' | xargs -I pkg bash -c 'cd $GOPATH/src/$0 && if echo -n "$0" | grep -vEq "^github.com/Psiphon-Labs/psiphon-tunnel-core/" ; then echo -n "\"$0\":\"$(git rev-parse --short HEAD)\"," ; fi' pkg | sed 's/,$//' | tr -d '\n' && echo -n "}")

  LDFLAGS="\
  -linkmode external -extldflags \"-static\" \
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

build_for_linux () {
  prepare_build linux
  GOOS=linux GOARCH=amd64 go build -v -x -tags "${BUILD_TAGS}" -ldflags "$LDFLAGS" -o psiphond
  if [ $? != 0 ]; then
    echo "...'go build' failed, exiting"
    exit $?
  fi
  chmod 555 psiphond

  if [ "$1" == "generate" ]; then
    ./psiphond --ipaddress 0.0.0.0 --web 3000 --protocol SSH:3001 --protocol OSSH:3002 --logFilename /var/log/psiphond/psiphond.log generate

    chmod 666 psiphond.config
    chmod 666 psiphond-traffic-rules.config
    chmod 666 psiphond-osl.config
    chmod 666 psiphond-tactics.config
    chmod 666 server-entry.dat
  fi

}

build_for_linux generate
echo "Done"
