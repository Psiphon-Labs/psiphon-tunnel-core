marionette
==========

This is a Go port of the [marionette][] programmable networy proxy.

## WebBrowser Demonstration

Please install Marionette as described below, and then go to the web browser
demonstration page [here](./BrowserDemo.md)


## Development

Marionette requires several dependencies to be installed first. Two of them
are in the `third_party` directory and the third one can be downloaded from
the web.

You can use the `./build_third_party.sh` script in the root of this repository
to build the third party libraries or follow the instructions below to manually
build them or install them system wide.

### Installing on CentOS

Ensure you have a C/C++ compiler installed:

```sh
$ yum group install -y "Development Tools"
```

### Installing OpenFST

You must use the included `third_party/openfst` implementation. Also note that
static builds must be enabled via the `--enable-static` flag.

```sh
$ cd third_party/openfst
$ ./configure --enable-static=yes
$ make
$ sudo make install
```


### Installing re2

You must use the included `third_party/re2` implementation:

```sh
$ cd third_party/re2
$ make
$ sudo make install
```


### GMP

Download the latest version of [GMP][], unpack the
archive and run:

```sh
$ wget https://gmplib.org/download/gmp/gmp-6.1.2.tar.bz2
$ tar -xvjf gmp-6.1.2.tar.bz2
$ cd gmp-6.1.2

$ ./configure --enable-cxx
$ make
$ sudo make install
$ make check
```



### Building the Marionette Binary

First, make sure you have installed Go from [https://golang.org/][go]. Next,
install `dep` using [these instructions][dep].

Finally, retrieve the source, update project dependencies, and install the
`marionette` binary:

```sh
$ go get github.com/redjack/marionette
$ cd $GOPATH/src/github.com/redjack/marionette
$ dep ensure
$ go install ./cmd/marionette
```

The `marionette` binary is now installed in your `$GOPATH/bin` folder.


[marionette]: https://github.com/marionette-tg/marionette
[GMP]: https://gmplib.org
[go]: https://golang.org/
[dep]: https://github.com/golang/dep#installation


## Installing new build-in formats

When adding new formats, you'll need to first install `go-bindata`:

```sh
$ go get -u github.com/jteeuwen/go-bindata/...
```

Then you can use `go generate` to convert the asset files to Go files:

```sh
$ go generate ./...
```

To install the original [marionette][] library for comparing tests, download
the latest version, unpack the archive and run:


## Testing

Use the built-in go testing command to run the unit tests:

```sh
$ go test ./...
```

If you have the original Python marionette installed then you can run tests
of the ports using the `python` tag:

```sh
$ go test -tags python ./regex2dfa
$ go test -tags python ./fte
```


## Demo

### HTTP-over-FTP

In this example, we'll mask our HTTP traffic as FTP packets.

First, follow the installation instructions above on your client & server machines.

Start the server proxy on your server machine and forward traffic to a server
such as `google.com`.

```sh
$ marionette server -format ftp_simple_blocking -proxy google.com:80
listening on [::]:2121, proxying to google.com:80
```

Start the client proxy on your client machine and connect to your server proxy.
Replace `$SERVER_IP` with the IP address of your server.

```sh
$ marionette client -format ftp_simple_blocking -server $SERVER_IP
listening on 127.0.0.1:8079, connected to <SERVER_IP>
```

Finally, send a `curl` to `127.0.0.1:8079` and you should see a response from
`google.com`:

```sh
$ curl 127.0.0.1:8079
```

