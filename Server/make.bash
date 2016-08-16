#!/usr/bin/env bash

set -e

BASE_DIR=$( cd "$(dirname "$0")" ; pwd -P )
cd $BASE_DIR

if [ ! -f make.bash ]; then
  echo "make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/Server"
  exit 1
fi

prepare_build () {
  BUILDINFOFILE="${EXE_BASENAME}_buildinfo.txt"
  BUILDDATE=$(date --iso-8601=seconds)
  BUILDREPO=$(git config --get remote.origin.url)
  BUILDREV=$(git rev-parse --short HEAD)
  GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')
  DEPENDENCIES=$(echo -n "{" && go list -f '{{range $dep := .Deps}}{{printf "%s\n" $dep}}{{end}}' | xargs go list -f '{{if not .Standard}}{{.ImportPath}}{{end}}' | xargs -I pkg bash -c 'cd $GOPATH/src/pkg && echo -n "\"pkg\":\"$(git rev-parse --short HEAD)\","' | sed 's/,$/}/')

  LDFLAGS="\
  -linkmode external -extldflags \"-static\" \
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

build_for_linux () {
  echo "Getting project dependencies (via go get) for Linux. Parameter is: '$1'"
  GOOS=linux GOARCH=amd64 go get -d -v ./...
  prepare_build
  if [ $? != 0 ]; then
    echo "...'go get' failed, exiting"
    exit $?
  fi

  GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o psiphond main.go
  if [ $? != 0 ]; then
    echo "...'go build' failed, exiting"
    exit $?
  fi
  chmod 555 psiphond

  if [ "$1" == "generate" ]; then
    ./psiphond --ipaddress 0.0.0.0 --web 3000 --protocol SSH:3001 --protocol OSSH:3002 --logFilename /var/log/psiphond/psiphond.log generate

    chmod 666 psiphond.config
    chmod 666 psiphond-traffic-rules.config
    chmod 666 server-entry.dat
  fi

}

build_for_linux generate
echo "Done"
