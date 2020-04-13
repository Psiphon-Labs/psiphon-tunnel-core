// go 1.13 and later when ForceAttemptHTTP2 was added
// +build go1.13

package filtertransport

import (
	"context"
	"net"
	"net/http"
	"time"
)

// DefaultTransport http.DefaultTransport that filters using DefaultFilter
var DefaultTransport = &http.Transport{
	// does not include ProxyFromEnvironment, makes no sense for filter
	// DialContext will be used if Dial is nil
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return FilterDial(ctx, network, addr, DefaultFilter, (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext)
	},
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}
