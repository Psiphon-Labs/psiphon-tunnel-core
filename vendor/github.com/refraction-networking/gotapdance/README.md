<p align="center">
<a href="https://refraction.network"><img src="https://user-images.githubusercontent.com/5443147/30133006-7c3019f4-930f-11e7-9f60-3df45ee13d9d.png" alt="refract"></a>
<h1 class="header-title" align="center">TapDance Client</h1>

<p align="center">TapDance is a free-to-use anti-censorship technology, protected from enumeration attacks.</p>
<p align="center">
<a href="https://travis-ci.org/refraction-networking/gotapdance"><img src="https://travis-ci.org/refraction-networking/gotapdance.svg?branch=master"></a>
<a href="https://godoc.org/github.com/refraction-networking/gotapdance/tapdance"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
	<a href="https://goreportcard.com/report/github.com/refraction-networking/gotapdance"><img src="https://goreportcard.com/badge/github.com/refraction-networking/gotapdance"></a>
</p>

# Build
## Download Golang and TapDance and dependencies
0. Install [Golang](https://golang.org/dl/) (currently tested against version 1.10 and latest).

1. Get source code for Go TapDance and all dependencies:

 ```bash
go get -d -u -t github.com/refraction-networking/gotapdance/...
```
Ignore the "no buildable Go source files" warning.

If you have outdated versions of libraries used, you might want to do `go get -u all`.

## Usage

 There are 3 supported ways to use TapDance:

 * [Command Line Interface client](cli)

 * [Psiphon](https://psiphon.ca/) Android app integrated TapDance as one of their transports.

 * Use tapdance directly from other Golang program:

```Golang
package main

import (
	"github.com/refraction-networking/gotapdance/tapdance"
	"fmt"
)

func main() {
    // first, copy ClientConf and roots files into assets directory
    // make sure assets directory is writable (only) by the td process
    tapdance.AssetsSetDir("./path/to/assets/dir/")

    tdConn, err := tapdance.Dial("tcp", "censoredsite.com:80")
    if err != nil {
        fmt.Printf("tapdance.Dial() failed: %+v\n", err)
        return
    }
    // tdConn implements standard net.Conn, allowing to use it like any other Golang conn with
    // Write(), Read(), Close() etc. It also allows to pass tdConn to functions that expect
    // net.Conn, such as tls.Client() making it easy to do tls handshake over TapDance conn.
    _, err = tdConn.Write([]byte("GET / HTTP/1.1\nHost: censoredsite.com\n\n"))
    if err != nil {
        fmt.Printf("tdConn.Write() failed: %+v\n", err)
        return
    }
    buf := make([]byte, 16384)
    _, err = tdConn.Read(buf)
    // ...
}
```

 * [CURRENTLY NOT MAINTAINED] Standalone TapDance mobile applications that use [Golang Bindings](gobind) as a shared library.

   * [Android application in Java](android)


 # Links

 [Refraction Networking](https://refraction.network) is an umberlla term for the family of similarly working technnologies.

 TapDance station code released for FOCI'17 on github: [refraction-networking/tapdance](https://github.com/refraction-networking/tapdance)

 Original 2014 paper: ["TapDance: End-to-Middle Anticensorship without Flow Blocking"](https://ericw.us/trow/tapdance-sec14.pdf)

 Newer(2017) paper that shows TapDance working at high-scale: ["An ISP-Scale Deployment of TapDance"](https://sfrolov.io/papers/foci17-paper-frolov_0.pdf)
