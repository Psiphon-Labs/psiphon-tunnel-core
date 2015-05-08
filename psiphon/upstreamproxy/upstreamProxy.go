package upstreamproxy

import (
	"golang.org/x/net/proxy"
	"net"
	"net/url"
        "fmt"
)

type DialFunc func(string, string) (net.Conn, error)

type UpstreamProxyConfig struct {
	ForwardDialFunc DialFunc
	ProxyURIString  string
}

// UpstreamProxyConfig implements proxy.Dialer interface
// so we can pass it to proxy.FromURL
func (u *UpstreamProxyConfig) Dial(network, addr string) (net.Conn, error) {
	return u.ForwardDialFunc(network, addr)
}

func NewProxyDialFunc(config *UpstreamProxyConfig) DialFunc {
	proxyURI, err := url.Parse(config.ProxyURIString)
	if err != nil {
		return func(network, addr string) (net.Conn, error) {
                    return nil,  fmt.Errorf("Upstream proxy URI parsing error: %v", err)
		}
	}

	dialer, err := proxy.FromURL(proxyURI, config)
	if err != nil {
		return func(network, addr string) (net.Conn, error) {
			return nil, err
		}
	}
	return dialer.Dial
}
