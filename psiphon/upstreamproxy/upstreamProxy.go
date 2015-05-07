package upstreamproxy

import (
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
)

type DialFunc func(string, string) (net.Conn, error)

type proxyType int

const (
	HTTP proxyType = iota
	SOCKS4A
	SOCKS5
)

type UpstreamProxyConfig struct {
	ForwardDialFunc DialFunc
	ProxyAddress    string
	ProxyType       proxyType
	Username        string
	Password        string
}

// UpstreamProxyConfig proxy.Dialer interface
// so we can pass it to proxy.FromURL
func (u *UpstreamProxyConfig) Dial(network, addr string) (net.Conn, error) {
	return u.ForwardDialFunc(network, addr)
}

func NewProxyDialer(config *UpstreamProxyConfig) DialFunc {
	proxyURI, err := makeProxyUri(config)
	if err != nil {
		return func(network, addr string) (net.Conn, error) {
			return nil, err
		}
	}
	dialer, err := proxy.FromURL(proxyURI, config)
	return dialer.Dial
}

func proxySchemeFromType(ptype proxyType) (string, error) {
	proxySchemeDict := map[proxyType]string{
		HTTP:    "http",
		SOCKS4A: "socks4a",
		SOCKS5:  "socks5",
	}
	if val, ok := proxySchemeDict[ptype]; ok {
		return val, nil
	}
	return "", errors.New("Unsupported proxy type")
}

func makeProxyUri(config *UpstreamProxyConfig) (*url.URL, error) {
	scheme, err := proxySchemeFromType(config.ProxyType)
	if err != nil {
		return nil, err
	}
	var uriUserInfo string
	if config.Username != "" {
		uriUserInfo = config.Username
	}
	if config.Password != "" {
		uriUserInfo = fmt.Sprint(uriUserInfo, ":", config.Password)
	}
	if uriUserInfo != "" {
		uriUserInfo = fmt.Sprint(uriUserInfo, "@")
	}
	proxyUriStr := fmt.Sprint(scheme, "://", uriUserInfo, config.ProxyAddress)

	return url.Parse(proxyUriStr)
}
