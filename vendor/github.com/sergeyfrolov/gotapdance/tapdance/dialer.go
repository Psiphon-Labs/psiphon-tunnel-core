package tapdance

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
)

var sessionsTotal CounterUint64

// Dialer contains options and implements advanced functions for establishing TapDance connection.
type Dialer struct {
	SplitFlows bool
	TcpDialer  func(context.Context, string, string) (net.Conn, error)
}

// Dial connects to the address on the named network.
//
// The only supported network at this time: "tcp".
// The address has the form "host:port".
// The host must be a literal IP address, or a host name that can be
// resolved to IP addresses.
// To avoid abuse, only certain whitelisted ports are allowed.
//
// Example: Dial("tcp", "golang.org:80")
func Dial(network, address string) (net.Conn, error) {
	var d Dialer
	return d.Dial(network, address)
}

// Dial connects to the address on the named network.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to the address on the named network using the provided context.
// Long deadline is strongly advised, since tapdance will try multiple decoys.
//
// The only supported network at this time: "tcp".
// The address has the form "host:port".
// The host must be a literal IP address, or a host name that can be
// resolved to IP addresses.
// To avoid abuse, only certain whitelisted ports are allowed.
//
// Example: Dial("tcp", "golang.org:80")
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: net.UnknownNetworkError(network)}
	}
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	flow, err := d.DialProxyContext(ctx)
	if err != nil {
		return nil, err
	}

	_, err = fmt.Fprintf(flow, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Padding:%s\r\n\r\n",
		address, address, getRandPadding(450, 780, 5))
	if err != nil {
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(flow), nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("TapDance station responded with " + resp.Status)
	}

	return flow, nil
}

// DialProxy establishes direct connection to TapDance station proxy.
// Users are expected to send HTTP CONNECT request next.
func (d *Dialer) DialProxy() (net.Conn, error) {
	return d.DialProxyContext(context.Background())
}

// DialProxy establishes direct connection to TapDance station proxy using the provided context.
// Users are expected to send HTTP CONNECT request next.
func (d *Dialer) DialProxyContext(ctx context.Context) (net.Conn, error) {
	if !d.SplitFlows {
		flow, err := makeTdFlow(flowBidirectional, nil)
		if err != nil {
			return nil, err
		}
		flow.tdRaw.TcpDialer = d.TcpDialer
		return flow, flow.DialContext(ctx)
	}
	return dialSplitFlow(ctx, d.TcpDialer)
}
