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
  chmod 555 psiphond

  if [ "$1" == "generate" ]; then
    ./psiphond --ipaddress 0.0.0.0 --protocol SSH:22 --protocol OSSH:53 --web 80 generate
    # Temporary:
    #  - Disable syslog integration until final strategy is chosen
    #  - Disable Fail2Ban integration until final strategy is chosen
    sed -i 's/"SyslogFacility": "user"/"SyslogFacility": ""/' psiphond.config
    sed -i 's/"Fail2BanFormat": "Authentication failure for psiphon-client from %s"/"Fail2BanFormat": ""/' psiphond.config

    chmod 666 psiphond.config
    chmod 666 psiphond-traffic-rules.config
    chmod 666 server-entry.dat
  fi

}

build_for_linux generate
echo "Done"
