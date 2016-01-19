##Psiphon Console Client README

###Building with Docker

Note that you may need to use `sudo docker` below, depending on your OS.

#####Create the build image:
  1. Run the command: `docker build --no-cache=true -t psiclient .` (this may take some time to complete)
  2. Once completed, verify that you see an image named `psiclient` when running: `docker images`

#####Run the build:
  *Ensure that the command below is run from within the `ConsoleClient` directory*

  ```bash
  cd .. && \
    docker run \
    --rm \
    -v $(pwd):/go/src/github.com/Psiphon-Labs/psiphon-tunnel-core \
    psiclient \
    /bin/bash -c 'cd /go/src/github.com/Psiphon-Labs/psiphon-tunnel-core/ConsoleClient && ./make.bash all' \
  ; cd -
  ```
This command can also be modified by:
 - replacing `all` with `windows`, `linux`, or `osx` as the first parameter to `make.bash` (as in `...&& ./make.bash windows`) to only build binaries for the operating system of choice
   - if `windows` or `linux` is specified as the first parameter, the second parameter can be passed as either `32` or `64` (as in `...&& ./make.bash windows 32`)to limit the builds to just one or the other (no second parameter means both will build)

When that command completes, the compiled binaries will be located in the `bin` directory (`./bin`, and everything under it will likely be owned by root, so be sure to `chown` to an appropriate user) under the current directory. The structure will be:
  ```
  bin
  ├── darwin
  │   └── psiphon-tunnel-core-x86_64
  ├── linux
  │   └── psiphon-tunnel-core-i686
  │   └── psiphon-tunnel-core-x86_64
  └── windows
      └── psiphon-tunnel-core-i686.exe
      └── psiphon-tunnel-core-x86_64.exe

  ```

### Building without Docker

See the [main README build section](../README.md#build)

### Creating a configuration file

See the [main README configuration section](../README.md#configure)
