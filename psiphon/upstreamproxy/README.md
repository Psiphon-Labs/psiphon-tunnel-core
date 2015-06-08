`upstreamproxy` Package
=======================

This provides upstream proxy support by extending golang.org/x/net/proxy package.

Currently supported protocols:
* SOCKS4 via `socks4a` URI scheme
* SOCKS5 via `socks5` URI scheme
* HTTP 'CONNECT' with Basic, Digest and NTLM Authentication via `http` URI scheme

# Usage

```
/* 
   Proxy URI examples:
   "http://proxyhost:8080"
   "socks5://user:password@proxyhost:1080"
   "http://NTDOMAIN\NTUser:password@proxyhost:3375"
*/

var proxyDialer psiphon.Dialer 
proxyDialer = NewProxyDialFunc((
            ForwardDialFunc: psiphon.NewTCPDialer(tcpDialerConfig),
            ProxyURIString: "http://user:password@proxyhost:8080"
            })
```

Note: `NewProxyDialFunc` returns `ForwardDialFunc` if `ProxyURIString` is empty
