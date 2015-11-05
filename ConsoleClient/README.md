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
    /bin/bash -c 'cd /go/src/github.com/Psiphon-Labs/psiphon-tunnel-core/ConsoleClient && ./make.bash' \
  ; cd -
  ```

When that command completes, the compiled binaries will be located in the `bin` directory (`./bin`, and everything under it will likely be owned by root, so be sure to `chown` to an appropriate user) under the current directory. The structure will be:
  ```
  bin
  ├── darwin
  │   └── psiphon-native-messaging-host-x86_64
  ├── linux
  │   └── psiphon-native-messaging-host-i686
  │   └── psiphon-native-messaging-host-x86_64
  └── windows
      └── psiphon-native-messaging-host-i686.exe
      └── psiphon-native-messaging-host-x86_64.exe

  ```

### Building without Docker

See the [main README build section](../README.md#build)

### Creating a configuration file

See the [main README configuration section](../README.md#configure)
