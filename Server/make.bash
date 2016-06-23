#!/usr/bin/env sh

set -e

BASE_DIR=$( cd "$(dirname "$0")" ; pwd -P )
cd $BASE_DIR

if [ ! -f make.bash ]; then
  echo "make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/Server"
  exit 1
fi

build_for_linux () {
  echo "Getting project dependencies (via go get) for Linux. Parameter is: '$1'"
  GOOS=linux GOARCH=amd64 go get -d -v ./...
  if [ $? != 0 ]; then
    echo "...'go get' failed, exiting"
    exit $?
  fi

  GOOS=linux GOARCH=amd64 go build --ldflags '-linkmode external -extldflags "-static"' -o psiphond main.go
  if [ $? != 0 ]; then
    echo "...'go build' failed, exiting"
    exit $?
  fi
  chmod 777 psiphond

}

build_for_linux
echo "Done"
