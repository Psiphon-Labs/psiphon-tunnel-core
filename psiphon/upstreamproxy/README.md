`upstreamproxy` Package
=======================

This provides upstream proxy support by extending golang.org/x/net/proxy package.

Currently supported protocols:
* SOCKS4 via `socks4a` URI scheme
* SOCKS5 via `socks5` URI scheme
* HTTP 'CONNECT' with Basic, Digest and NTLM Authentication via `http` URI scheme

# Usage

Note: `NewProxyDialFunc` returns `ForwardDialFunc` if `ProxyURIString` is empty

```
/* 
   Proxy URI examples:
   "http://proxyhost:8080"
   "socks5://user:password@proxyhost:1080"
   "http://NTDOMAIN\NTUser:password@proxyhost:3375"
*/

//Plain HTTP transport via HTTP proxy
func doAuthenticatedHTTP() {
	proxyUrl, err := url.Parse("http://user:password@172.16.1.1:8080")
	transport := &http.Transport{Proxy: http.ProxyURL(proxyUrl)}
	customHeader := http.Header{"Test" :{"test"}}

	authHttpTransport, err := upstreamproxy.NewProxyAuthTransport(transport, customHeader)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	r, err := http.NewRequest("GET", "http://www.reddit.com", bytes.NewReader(data))
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	resp, err := authHttpTransport.RoundTrip(r)
	if err != nil {
		fmt.Println("RoundTrip Error: ", err)
		return
	}
	ioutil.ReadAll(resp.Body)
	fmt.Println(string(resp.Status))
}

//HTTPS transport via HTTP proxy
func doAuthenticatedHTTPS() {
	dialTlsFn := func(netw, addr string) (net.Conn, error) {
		config := &upstreamproxy.UpstreamProxyConfig{
			ForwardDialFunc: net.Dial,
			ProxyURIString:  "http://user:password@172.16.1.1:8080",
		}

		proxyDialFunc := upstreamproxy.NewProxyDialFunc(config)

		conn, err := proxyDialFunc(netw, addr)
		if err != nil {
			return nil, err
		}
		tlsconfig := &tls.Config{InsecureSkipVerify: false}
		tlsConn := tls.Client(conn, tlsconfig)

		return tlsConn, tlsConn.Handshake()
	}

	r, err := http.NewRequest("GET", "https://www.reddit.com", bytes.NewReader(data))
	transport = &http.Transport{DialTLS: dialTlsFn}
	resp, err := transport.RoundTrip(r)
	if err != nil {
		log.Println("RoundTrip Error: ", err)
		return
	}
	ioutil.ReadAll(resp.Body)
	fmt.Println(string(resp.Status))
}

//HTTP transport via SOCKS5 proxy
func doAuthenticatedHttpSocks() {
	dialFn := func(netw, addr string) (net.Conn, error) {
		config := &upstreamproxy.UpstreamProxyConfig{
			ForwardDialFunc: net.Dial,
			ProxyURIString:  "socks5://user:password@172.16.1.1:5555",
		}

		proxyDialFunc := upstreamproxy.NewProxyDialFunc(config)

		return proxyDialFunc(netw, addr)
	}

	r, err := http.NewRequest("GET", "https://www.reddit.com", bytes.NewReader(data))
	transport = &http.Transport{Dial: dialFn}
	resp, err := transport.RoundTrip(r)
	if err != nil {
		log.Println("RoundTrip Error: ", err)
		return
	}
	ioutil.ReadAll(resp.Body)
	fmt.Println(string(resp.Status))
}
```

