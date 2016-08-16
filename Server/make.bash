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
  BUILDDATE=$(date -Iseconds)
  BUILDREPO=$(git config --get remote.origin.url)
  BUILDREV=$(git rev-parse --short HEAD)
  GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')

  # - starts the string with a `{`
  # - uses the `go list` command and passes it a template string (using the Go template syntax) saying I want all the dependencies of the package in the current directory, printing 1/line via printf
  # - pipes to `xargs` to run a command on each line output from the first command
  #  - uses `go list` with a template string to print the "Import Path" (from just below `$GOPATH/src`) if the package is not part of the standard library
  # - pipes to `xargs` again, specifiying `pkg` as the placeholder name for each item being operated on (which is the list of non standard library import paths from the previous step)
  #  - `xargs` runs a bash script (via `-c`) which changes to each import path in sequence, then echoes out `"<import path>":"<subshell output of getting the short git revision>",`
  # - this leaves a trailing `,` at the end, and no close to the JSON object, so simply `sed` replace the comma before the end of the line with `}` and you now have valid JSON
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
