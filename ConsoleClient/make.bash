#!/usr/bin/env bash

set -e
#set -xv # verbose output for testing

if [ ! -f make.bash ]; then
  echo 'make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/ConsoleClient'
  exit 1
fi

CGO_ENABLED=1

# Make sure we have our dependencies
echo -e "go-getting dependencies...\n"
go get -d -v ./...

LDFLAGS="\
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildDate `date --iso-8601=seconds` \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRepo `git config --get remote.origin.url` \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRev `git rev-parse HEAD` \
"
echo -e "LDFLAGS=$LDFLAGS\n"

echo -e "\nBuilding windows-386..."
CC=/usr/bin/i686-w64-mingw32-gcc \
  gox -verbose -ldflags "$LDFLAGS" -osarch windows/386 -output windows_386_psiphon-tunnel-core
# We are finding that UPXing the full Windows Psiphon client produces better results
# if psiphon-tunnel-core.exe is not already UPX'd.
#upx --best windows_386_psiphon-tunnel-core.exe

echo -e "\nBuilding windows-amd64..."
CC=/usr/bin/x86_64-w64-mingw32-gcc \
  gox -verbose -ldflags "$LDFLAGS" -osarch windows/amd64 -output windows_amd64_psiphon-tunnel-core
upx --best windows_amd64_psiphon-tunnel-core.exe

echo -e "\nBuilding linux-amd64..."
gox -verbose -ldflags "$LDFLAGS" -osarch linux/amd64 -output linux_amd64_psiphon-tunnel-core
upx --best linux_amd64_psiphon-tunnel-core

echo -e "\nBuilding linux-386..."
CFLAGS=-m32 \
  gox -verbose -ldflags "$LDFLAGS" -osarch linux/386 -output linux_386_psiphon-tunnel-core
upx --best linux_386_psiphon-tunnel-core
