## Psiphon Tunnel Core Server README

### Overview
The `Server`/`psiphond` program and the `github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server` package contain the Psiphon server software.

Functionality is based on the [legacy server stack](https://bitbucket.org/psiphon/psiphon-circumvention-system/src/tip/Server/). `psiphond` has entered production.

### Build
Prerequisites:
 - Go 1.9 or later

Build Steps:
 - Get dependencies: `go get -d -v ./...`
 - Build: `go build -o psiphond main.go` (will generate a binary named `psiphond` for Linux/OSX  or `psiphond.exe` for Windows)

