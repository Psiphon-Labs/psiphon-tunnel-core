/*
 * Copyright (c) 2015, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package psiphon

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"time"

	"github.com/Psiphon-Inc/dns"
)

const DNS_PORT = 53

// DialConfig contains parameters to determine the behavior
// of a Psiphon dialer (TCPDial, MeekDial, etc.)
type DialConfig struct {

	// UpstreamProxyUrl specifies a proxy to connect through.
	// E.g., "http://proxyhost:8080"
	//       "socks5://user:password@proxyhost:1080"
	//       "socks4a://proxyhost:1080"
	//       "http://NTDOMAIN\NTUser:password@proxyhost:3375"
	//
	// Certain tunnel protocols require HTTP CONNECT support
	// when a HTTP proxy is specified. If CONNECT is not
	// supported, those protocols will not connect.
	UpstreamProxyUrl string

	ConnectTimeout time.Duration

	// PendingConns is used to track and interrupt dials in progress.
	// Dials may be interrupted using PendingConns.CloseAll(). Once instantiated,
	// a conn is added to pendingConns before the network connect begins and
	// removed from pendingConns once the connect succeeds or fails.
	PendingConns *Conns

	// BindToDevice parameters are used to exclude connections and
	// associated DNS requests from VPN routing.
	// When DeviceBinder is set, any underlying socket is
	// submitted to the device binding servicebefore connecting.
	// The service should bind the socket to a device so that it doesn't route
	// through a VPN interface. This service is also used to bind UDP sockets used
	// for DNS requests, in which case DnsServerGetter is used to get the
	// current active untunneled network DNS server.
	DeviceBinder    DeviceBinder
	DnsServerGetter DnsServerGetter

	// UseIndistinguishableTLS specifies whether to try to use an
	// alternative stack for TLS. From a circumvention perspective,
	// Go's TLS has a distinct fingerprint that may be used for blocking.
	// Only applies to TLS connections.
	UseIndistinguishableTLS bool

	// TrustedCACertificatesFilename specifies a file containing trusted
	// CA certs. The file contents should be compatible with OpenSSL's
	// SSL_CTX_load_verify_locations.
	// Only applies to UseIndistinguishableTLS connections.
	TrustedCACertificatesFilename string

	// DeviceRegion is the reported region the host device is running in.
	// When set, this value may be used, pre-connection, to select performance
	// or circumvention optimization strategies for the given region.
	DeviceRegion string

	// ResolvedIPCallback, when set, is called with the IP address that was
	// dialed. This is either the specified IP address in the dial address,
	// or the resolved IP address in the case where the dial address is a
	// domain name.
	// The callback may be invoked by a concurrent goroutine.
	ResolvedIPCallback func(string)
}

// DeviceBinder defines the interface to the external BindToDevice provider
type DeviceBinder interface {
	BindToDevice(fileDescriptor int) error
}

// NetworkConnectivityChecker defines the interface to the external
// HasNetworkConnectivity provider
type NetworkConnectivityChecker interface {
	// TODO: change to bool return value once gobind supports that type
	HasNetworkConnectivity() int
}

// DnsServerGetter defines the interface to the external GetDnsServer provider
type DnsServerGetter interface {
	GetPrimaryDnsServer() string
	GetSecondaryDnsServer() string
}

// TimeoutError implements the error interface
type TimeoutError struct{}

func (TimeoutError) Error() string   { return "timed out" }
func (TimeoutError) Timeout() bool   { return true }
func (TimeoutError) Temporary() bool { return true }

// Dialer is a custom dialer compatible with http.Transport.Dial.
type Dialer func(string, string) (net.Conn, error)

// Conns is a synchronized list of Conns that is used to coordinate
// interrupting a set of goroutines establishing connections, or
// close a set of open connections, etc.
// Once the list is closed, no more items may be added to the
// list (unless it is reset).
type Conns struct {
	mutex    sync.Mutex
	isClosed bool
	conns    map[net.Conn]bool
}

func (conns *Conns) Reset() {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	conns.isClosed = false
	conns.conns = make(map[net.Conn]bool)
}

func (conns *Conns) Add(conn net.Conn) bool {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	if conns.isClosed {
		return false
	}
	if conns.conns == nil {
		conns.conns = make(map[net.Conn]bool)
	}
	conns.conns[conn] = true
	return true
}

func (conns *Conns) Remove(conn net.Conn) {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	delete(conns.conns, conn)
}

func (conns *Conns) CloseAll() {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	conns.isClosed = true
	for conn, _ := range conns.conns {
		conn.Close()
	}
	conns.conns = make(map[net.Conn]bool)
}

// LocalProxyRelay sends to remoteConn bytes received from localConn,
// and sends to localConn bytes received from remoteConn.
func LocalProxyRelay(proxyType string, localConn, remoteConn net.Conn) {
	copyWaitGroup := new(sync.WaitGroup)
	copyWaitGroup.Add(1)
	go func() {
		defer copyWaitGroup.Done()
		_, err := io.Copy(localConn, remoteConn)
		if err != nil {
			err = fmt.Errorf("Relay failed: %s", ContextError(err))
			NoticeLocalProxyError(proxyType, err)
		}
	}()
	_, err := io.Copy(remoteConn, localConn)
	if err != nil {
		err = fmt.Errorf("Relay failed: %s", ContextError(err))
		NoticeLocalProxyError(proxyType, err)
	}
	copyWaitGroup.Wait()
}

// WaitForNetworkConnectivity uses a NetworkConnectivityChecker to
// periodically check for network connectivity. It returns true if
// no NetworkConnectivityChecker is provided (waiting is disabled)
// or when NetworkConnectivityChecker.HasNetworkConnectivity()
// indicates connectivity. It waits and polls the checker once a second.
// If any stop is broadcast, false is returned immediately.
func WaitForNetworkConnectivity(
	connectivityChecker NetworkConnectivityChecker, stopBroadcasts ...<-chan struct{}) bool {
	if connectivityChecker == nil || 1 == connectivityChecker.HasNetworkConnectivity() {
		return true
	}
	NoticeInfo("waiting for network connectivity")
	ticker := time.NewTicker(1 * time.Second)
	for {
		if 1 == connectivityChecker.HasNetworkConnectivity() {
			return true
		}

		selectCases := make([]reflect.SelectCase, 1+len(stopBroadcasts))
		selectCases[0] = reflect.SelectCase{
			Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ticker.C)}
		for i, stopBroadcast := range stopBroadcasts {
			selectCases[i+1] = reflect.SelectCase{
				Dir: reflect.SelectRecv, Chan: reflect.ValueOf(stopBroadcast)}
		}

		chosen, _, ok := reflect.Select(selectCases)
		if chosen == 0 && ok {
			// Ticker case, so check again
		} else {
			// Stop case
			return false
		}
	}
}

// ResolveIP uses a custom dns stack to make a DNS query over the
// given TCP or UDP conn. This is used, e.g., when we need to ensure
// that a DNS connection bypasses a VPN interface (BindToDevice) or
// when we need to ensure that a DNS connection is tunneled.
// Caller must set timeouts or interruptibility as required for conn.
func ResolveIP(host string, conn net.Conn) (addrs []net.IP, ttls []time.Duration, err error) {

	// Send the DNS query
	dnsConn := &dns.Conn{Conn: conn}
	defer dnsConn.Close()
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(host), dns.TypeA)
	query.RecursionDesired = true
	dnsConn.WriteMsg(query)

	// Process the response
	response, err := dnsConn.ReadMsg()
	if err != nil {
		return nil, nil, ContextError(err)
	}
	addrs = make([]net.IP, 0)
	ttls = make([]time.Duration, 0)
	for _, answer := range response.Answer {
		if a, ok := answer.(*dns.A); ok {
			addrs = append(addrs, a.A)
			ttl := time.Duration(a.Hdr.Ttl) * time.Second
			ttls = append(ttls, ttl)
		}
	}
	return addrs, ttls, nil
}

// MakeUntunneledHttpsClient returns a net/http.Client which is
// configured to use custom dialing features -- including BindToDevice,
// UseIndistinguishableTLS, etc. -- for a specific HTTPS request URL.
// If verifyLegacyCertificate is not nil, it's used for certificate
// verification.
// Because UseIndistinguishableTLS requires a hack to work with
// net/http, MakeUntunneledHttpClient may return a modified request URL
// to be used. Callers should always use this return value to make
// requests, not the input value.
func MakeUntunneledHttpsClient(
	dialConfig *DialConfig,
	verifyLegacyCertificate *x509.Certificate,
	requestUrl string,
	requestTimeout time.Duration) (*http.Client, string, error) {

	dialer := NewCustomTLSDialer(
		// Note: when verifyLegacyCertificate is not nil, some
		// of the other CustomTLSConfig is overridden.
		&CustomTLSConfig{
			Dial: NewTCPDialer(dialConfig),
			VerifyLegacyCertificate:       verifyLegacyCertificate,
			SendServerName:                true,
			SkipVerify:                    false,
			UseIndistinguishableTLS:       dialConfig.UseIndistinguishableTLS,
			TrustedCACertificatesFilename: dialConfig.TrustedCACertificatesFilename,
		})

	urlComponents, err := url.Parse(requestUrl)
	if err != nil {
		return nil, "", ContextError(err)
	}

	// Change the scheme to "http"; otherwise http.Transport will try to do
	// another TLS handshake inside the explicit TLS session. Also need to
	// force an explicit port, as the default for "http", 80, won't talk TLS.
	urlComponents.Scheme = "http"
	host, port, err := net.SplitHostPort(urlComponents.Host)
	if err != nil {
		// Assume there's no port
		host = urlComponents.Host
		port = ""
	}
	if port == "" {
		port = "443"
	}
	urlComponents.Host = net.JoinHostPort(host, port)

	transport := &http.Transport{
		Dial: dialer,
	}
	httpClient := &http.Client{
		Timeout:   requestTimeout,
		Transport: transport,
	}

	return httpClient, urlComponents.String(), nil
}

// MakeTunneledHttpClient returns a net/http.Client which is
// configured to use custom dialing features including tunneled
// dialing and, optionally, UseTrustedCACertificatesForStockTLS.
// Unlike MakeUntunneledHttpsClient and makePsiphonHttpsClient,
// This http.Client uses stock TLS and no scheme transformation
// hack is required.
func MakeTunneledHttpClient(
	config *Config,
	tunnel *Tunnel,
	requestTimeout time.Duration) (*http.Client, error) {

	tunneledDialer := func(_, addr string) (conn net.Conn, err error) {
		return tunnel.sshClient.Dial("tcp", addr)
	}

	transport := &http.Transport{
		Dial: tunneledDialer,
		ResponseHeaderTimeout: requestTimeout,
	}

	if config.UseTrustedCACertificatesForStockTLS {
		if config.TrustedCACertificatesFilename == "" {
			return nil, ContextError(errors.New(
				"UseTrustedCACertificatesForStockTLS requires TrustedCACertificatesFilename"))
		}
		rootCAs := x509.NewCertPool()
		certData, err := ioutil.ReadFile(config.TrustedCACertificatesFilename)
		if err != nil {
			return nil, ContextError(err)
		}
		rootCAs.AppendCertsFromPEM(certData)
		transport.TLSClientConfig = &tls.Config{RootCAs: rootCAs}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
	}, nil
}
