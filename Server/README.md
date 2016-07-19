## Psiphon Tunnel Core Server README

### Overview
The `Server`/`psiphond` program and the `github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server` package contain an experimental Psiphon server stack.

Functionality is based on the [production server stack](https://bitbucket.org/psiphon/psiphon-circumvention-system/src/tip/Server/) but only a small subset is implemented. Currently, this stack supports the `SSH` and `OSSH` protocols and has a minimal web server to support the API calls the tunnel-core client requires.

### Build
Prerequisites:
 - Go 1.6.2 or later

Build Steps:
 - Get dependencies: `go get -d -v ./...`
 - Build: `go build -o psiphond main.go` (will generate a binary named `psiphond` for Linux/OSX  or `psiphond.exe` for Windows)

#### MUSL `libc` build (for Alpine Linux on Docker)
Prerequisites:
 - Go 1.6.2 or later
 - Docker 1.10 or later
 - MUSL libc toolchain

##### Building MUSL
 1. Clone the latest source (master is stable): `git clone git://git.musl-libc.org/musl`
 2. Change into the musl directory: `cd musl`
 3. Configure the build environment: `./configure`
 4. Build the libraries and toolchain binaries: `make`
 5. Install: `sudo make install`
    - Installs to `/usr/local/musl` by default, change by passing `--prefix <path>` as a flag to the configure script in step 3

##### Building the binary with MUSL for Docker
Build Steps:
 - Get dependencies: `GOOS=linux GOARCH=amd64 go get -d -v ./...`
 - Build: `GOOS=linux GOARCH=amd64 CC=/usr/local/musl/bin/musl-gcc go build --ldflags '-linkmode external -extldflags "-static"' -o psiphond main.go` (will generate a statically linked binary named `psiphond`)

**NOTE**: If you have ever used a _GNU libc_ based build of this project, you will need to append the `-a` flag to your `go build` command in order to force rebuilding of previously built libraries. Additionally, compiling with the _GNU libc_ again (after having compiled with _MUSL libc_) will also require the `-a` flag.

Updated build command: `GOOS=linux GOARCH=amd64 CC=/usr/local/musl/bin/musl-gcc go build -a --ldflags '-linkmode external -extldflags "-static"' -o psiphond main.go`

##### Building the binary with MUSL in Docker

You may also use the `Dockerfile-binary-builder` docker file to create an image that will be able to build the binary for you without installing MUSL and cross-compiling locally.

1. Build the image: `docker build -f Dockerfile-binary-builder -t psiphond-builder .`
2. Run the build via the image: `docker run --rm -v $PWD/../:/go/src/github.com/Psiphon-Labs/psiphon-tunnel-core psiphond-builder`
3. Change the owner (if desired) of the `psiphond` binary. The permissions are `777`/`a+rwx`, but the owner and group will both be `root`. Functionally, this should not matter at all.

##### Generate a configuration file
 1. Use the command `./psiphond --help` to get a list of flags to pass to the `generate` sub-command
 2. Run: `./psiphond --ipaddress 0.0.0.0 --web 3000 --protocol SSH:3001 --protocol OSSH:3002 --logFilename /var/log/psiphon/psiphond.log generate` (IP address `0.0.0.0` is used due to how docker handles services bound to the loopback device)


##### Create the Docker image:
 1. Run the command: `docker build --no-cache=true -t psiphond .` (this may take some time to complete)
    - Subsequent updates can be built without the `--no-cache=true` flag to speed up builds
 2. Once completed, verify that you see an image named `psiphond` when running: `docker images`

### Usage
- Execute `./psiphond generate` to generate a server configuration, including new key material and credentials. This will emit a config file and a server entry file.
 - Note: `generate` does not yet take input parameters, so for now you must edit code if you must change the server IP address or ports.
- Execute `./psiphond run` to run the server stack using the generated configuration.
- Copy the contents of the server entry file to the client (e.g., the `TargetServerEntry` config field in the tunnel-core client) to connect to the server.

#### Run the docker image
Run the docker container built above as follows: `docker run -d --name psiphond-1 -p 13000:3000 -p 13001:3001 -p 13002:3002 psiphond`

This will start a daemonized container, running the tunnel core server named `psiphond-1`, with `host:container` port mappings:
 - 13000:3000
 - 13001:3001
 - 13002:3002

 The container can be stopped by issuing the command `docker stop psiphond-1`. It will send the server a `SIGTERM`, followed by a `SIGKILL` if it is still running after a grace period

 The container logs can be viewed/tailed/etc via the `docker logs psiphond-1` command and the various flags the `logs` subcommand allows
