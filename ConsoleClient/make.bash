#!/usr/bin/env bash

set -e

if [ ! -f make.bash ]; then
  echo 'make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/ConsoleClient'
  exit 1
fi

# Make sure we have our dependencies
echo 'go-getting dependencies...'
go get -d -v ./...

CGO_ENABLED=1

echo 'Building windows-386...'
CC=/usr/bin/i686-w64-mingw32-gcc \
  gox -verbose -osarch windows/386 -output windows_386_psiphon-tunnel-core
upx --best windows_386_psiphon-tunnel-core.exe

echo 'Building windows-amd64...'
CC=/usr/bin/x86_64-w64-mingw32-gcc \
  gox -verbose -osarch windows/amd64 -output windows_amd64_psiphon-tunnel-core
upx --best windows_amd64_psiphon-tunnel-core.exe

echo 'Building linux-amd64...'
gox -verbose -osarch linux/amd64 -output linux_amd64_psiphon-tunnel-core
upx --best linux_amd64_psiphon-tunnel-core
