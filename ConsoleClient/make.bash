#!/usr/bin/env bash

set -e

if [ ! -f make.bash ]; then
  echo 'make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/ConsoleClient'
  exit 1
fi

# Make sure we have our dependencies
echo 'go-getting dependencies...'
go get -d -v ./...

echo 'Building windows-386 executable...'
CGO_ENABLED=1 GOOS=windows GOARCH=386 \
  go build -a -v -o psiphon-tunnel-core.exe
upx --best psiphon-tunnel-core.exe

mkdir -p windows_386
mv -f psiphon-tunnel-core.exe windows_386/psiphon-tunnel-core.exe

echo 'Windows executable can be found at: windows_386/psiphon-tunnel-core.exe'
