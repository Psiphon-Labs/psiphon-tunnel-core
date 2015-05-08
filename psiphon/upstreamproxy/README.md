`upstreamproxy` Package
=======================

This provides upstream proxy support by extending golang.org/x/net/proxy package.

Currently supported protocols:
* SOCKS4 via `socks4a` URI scheme
* SOCKS5 via `socks5` URI scheme
* HTTP with Basic Auth via `http` URI scheme

# Usage

```
var proxyDialer psiphon.Dialer 
proxyDialer = NewProxyDialFunc((
            ForwardDialFunc: psiphon.NewTCPDialer(tcpDialerConfig),
            ProxyURIString: "http://user:password@proxyhost:8080"
            })
```



