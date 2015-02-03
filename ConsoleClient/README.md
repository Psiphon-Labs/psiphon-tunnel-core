Psiphon Console Client README
================================================================================

### Building with Docker

Note that you may need to use `sudo docker` below, depending on your OS.

Create the build image:

```bash
# While in the same directory as the Dockerfile...
$ docker build --no-cache=true -t psigoconsole .
# That will take a long time to complete.
# After it's done, you'll have an image called "psigoconsole". Check with...
$ docker images
```

To do the build:

```bash
$ docker run --rm -v $GOPATH/src:/src psigoconsole /bin/bash -c 'cd /src/github.com/Psiphon-Labs/psiphon-tunnel-core/ConsoleClient && ./make.bash'
```

When that command completes, the compiled library will be located at `windows_386/psiphon-tunnel-core.exe`.
