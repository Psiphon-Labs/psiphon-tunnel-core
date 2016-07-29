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
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/Psiphon-Inc/dns"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
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

	// UpstreamProxyCustomHeader is a set of additional arbitrary HTTP headers that are
	// added to all HTTP requests made through the upstream proxy specified by UpstreamProxyUrl
	// in case of HTTP proxy
	UpstreamProxyCustomHeaders http.Header

	ConnectTimeout time.Duration

	// PendingConns is used to track and interrupt dials in progress.
	// Dials may be interrupted using PendingConns.CloseAll(). Once instantiated,
	// a conn is added to pendingConns before the network connect begins and
	// removed from pendingConns once the connect succeeds or fails.
	// May be nil.
	PendingConns *common.Conns

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

// NetworkConnectivityChecker defines the interface to the external
// HasNetworkConnectivity provider
type NetworkConnectivityChecker interface {
	// TODO: change to bool return value once gobind supports that type
	HasNetworkConnectivity() int
}

// DeviceBinder defines the interface to the external BindToDevice provider
type DeviceBinder interface {
	BindToDevice(fileDescriptor int) error
}

// DnsServerGetter defines the interface to the external GetDnsServer provider
type DnsServerGetter interface {
	GetPrimaryDnsServer() string
	GetSecondaryDnsServer() string
}

// HostNameTransformer defines the interface for pluggable hostname
// transformation circumvention strategies.
type HostNameTransformer interface {
	TransformHostName(hostname string) (string, bool)
}

// IdentityHostNameTransformer is the default HostNameTransformer, which
// returns the hostname unchanged.
type IdentityHostNameTransformer struct{}

func (IdentityHostNameTransformer) TransformHostName(hostname string) (string, bool) {
	return hostname, false
}

// TimeoutError implements the error interface
type TimeoutError struct{}

func (TimeoutError) Error() string   { return "timed out" }
func (TimeoutError) Timeout() bool   { return true }
func (TimeoutError) Temporary() bool { return true }

// Dialer is a custom dialer compatible with http.Transport.Dial.
type Dialer func(string, string) (net.Conn, error)

// LocalProxyRelay sends to remoteConn bytes received from localConn,
// and sends to localConn bytes received from remoteConn.
func LocalProxyRelay(proxyType string, localConn, remoteConn net.Conn) {
	copyWaitGroup := new(sync.WaitGroup)
	copyWaitGroup.Add(1)
	go func() {
		defer copyWaitGroup.Done()
		_, err := io.Copy(localConn, remoteConn)
		if err != nil {
			err = fmt.Errorf("Relay failed: %s", common.ContextError(err))
			NoticeLocalProxyError(proxyType, err)
		}
	}()
	_, err := io.Copy(remoteConn, localConn)
	if err != nil {
		err = fmt.Errorf("Relay failed: %s", common.ContextError(err))
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
		return nil, nil, common.ContextError(err)
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

	// Change the scheme to "http"; otherwise http.Transport will try to do
	// another TLS handshake inside the explicit TLS session. Also need to
	// force an explicit port, as the default for "http", 80, won't talk TLS.

	urlComponents, err := url.Parse(requestUrl)
	if err != nil {
		return nil, "", common.ContextError(err)
	}

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

	// Note: IndistinguishableTLS mode doesn't support VerifyLegacyCertificate
	useIndistinguishableTLS := dialConfig.UseIndistinguishableTLS && verifyLegacyCertificate == nil

	dialer := NewCustomTLSDialer(
		// Note: when verifyLegacyCertificate is not nil, some
		// of the other CustomTLSConfig is overridden.
		&CustomTLSConfig{
			Dial: NewTCPDialer(dialConfig),
			VerifyLegacyCertificate:       verifyLegacyCertificate,
			SNIServerName:                 host,
			SkipVerify:                    false,
			UseIndistinguishableTLS:       useIndistinguishableTLS,
			TrustedCACertificatesFilename: dialConfig.TrustedCACertificatesFilename,
		})

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
	}

	if config.UseTrustedCACertificatesForStockTLS {
		if config.TrustedCACertificatesFilename == "" {
			return nil, common.ContextError(errors.New(
				"UseTrustedCACertificatesForStockTLS requires TrustedCACertificatesFilename"))
		}
		rootCAs := x509.NewCertPool()
		certData, err := ioutil.ReadFile(config.TrustedCACertificatesFilename)
		if err != nil {
			return nil, common.ContextError(err)
		}
		rootCAs.AppendCertsFromPEM(certData)
		transport.TLSClientConfig = &tls.Config{RootCAs: rootCAs}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
	}, nil
}

// MakeDownloadHttpClient is a resusable helper that sets up a
// http.Client for use either untunneled or through a tunnel.
// See MakeUntunneledHttpsClient for a note about request URL
// rewritting.
func MakeDownloadHttpClient(
	config *Config,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig,
	requestUrl string,
	requestTimeout time.Duration) (*http.Client, string, error) {

	var httpClient *http.Client
	var err error

	if tunnel != nil {
		httpClient, err = MakeTunneledHttpClient(config, tunnel, requestTimeout)
		if err != nil {
			return nil, "", common.ContextError(err)
		}
	} else {
		httpClient, requestUrl, err = MakeUntunneledHttpsClient(
			untunneledDialConfig, nil, requestUrl, requestTimeout)
		if err != nil {
			return nil, "", common.ContextError(err)
		}
	}

	return httpClient, requestUrl, nil
}

// ResumeDownload is a resuable helper that downloads requestUrl via the
// httpClient, storing the result in downloadFilename when the download is
// complete. Intermediate, partial downloads state is stored in
// downloadFilename.part and downloadFilename.part.etag.
// Any existing downloadFilename file will be overwritten.
//
// In the case where the remote object has change while a partial download
// is to be resumed, the partial state is reset and resumeDownload fails.
// The caller must restart the download.
//
// When ifNoneMatchETag is specified, no download is made if the remote
// object has the same ETag. ifNoneMatchETag has an effect only when no
// partial download is in progress.
//
func ResumeDownload(
	httpClient *http.Client,
	requestUrl string,
	downloadFilename string,
	ifNoneMatchETag string) (int64, string, error) {

	partialFilename := fmt.Sprintf("%s.part", downloadFilename)

	partialETagFilename := fmt.Sprintf("%s.part.etag", downloadFilename)

	file, err := os.OpenFile(partialFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return 0, "", common.ContextError(err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return 0, "", common.ContextError(err)
	}

	// A partial download should have an ETag which is to be sent with the
	// Range request to ensure that the source object is the same as the
	// one that is partially downloaded.
	var partialETag []byte
	if fileInfo.Size() > 0 {

		partialETag, err = ioutil.ReadFile(partialETagFilename)

		// When the ETag can't be loaded, delete the partial download. To keep the
		// code simple, there is no immediate, inline retry here, on the assumption
		// that the controller's upgradeDownloader will shortly call DownloadUpgrade
		// again.
		if err != nil {
			os.Remove(partialFilename)
			os.Remove(partialETagFilename)
			return 0, "", common.ContextError(
				fmt.Errorf("failed to load partial download ETag: %s", err))
		}
	}

	request, err := http.NewRequest("GET", requestUrl, nil)
	if err != nil {
		return 0, "", common.ContextError(err)
	}

	request.Header.Add("Range", fmt.Sprintf("bytes=%d-", fileInfo.Size()))

	if partialETag != nil {

		// Note: not using If-Range, since not all host servers support it.
		// Using If-Match means we need to check for status code 412 and reset
		// when the ETag has changed since the last partial download.
		request.Header.Add("If-Match", string(partialETag))

	} else if ifNoneMatchETag != "" {

		// Can't specify both If-Match and If-None-Match. Behavior is undefined.
		// https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.26
		// So for downloaders that store an ETag and wish to use that to prevent
		// redundant downloads, that ETag is sent as If-None-Match in the case
		// where a partial download is not in progress. When a partial download
		// is in progress, the partial ETag is sent as If-Match: either that's
		// a version that was never fully received, or it's no longer current in
		// which case the response will be StatusPreconditionFailed, the partial
		// download will be discarded, and then the next retry will use
		// If-None-Match.

		// Note: in this case, fileInfo.Size() == 0

		request.Header.Add("If-None-Match", ifNoneMatchETag)
	}

	response, err := httpClient.Do(request)

	// The resumeable download may ask for bytes past the resource range
	// since it doesn't store the "completed download" state. In this case,
	// the HTTP server returns 416. Otherwise, we expect 206. We may also
	// receive 412 on ETag mismatch.
	if err == nil &&
		(response.StatusCode != http.StatusPartialContent &&
			response.StatusCode != http.StatusRequestedRangeNotSatisfiable &&
			response.StatusCode != http.StatusPreconditionFailed &&
			response.StatusCode != http.StatusNotModified) {
		response.Body.Close()
		err = fmt.Errorf("unexpected response status code: %d", response.StatusCode)
	}
	if err != nil {
		return 0, "", common.ContextError(err)
	}
	defer response.Body.Close()

	responseETag := response.Header.Get("ETag")

	if response.StatusCode == http.StatusPreconditionFailed {
		// When the ETag no longer matches, delete the partial download. As above,
		// simply failing and relying on the caller's retry schedule.
		os.Remove(partialFilename)
		os.Remove(partialETagFilename)
		return 0, "", common.ContextError(errors.New("partial download ETag mismatch"))

	} else if response.StatusCode == http.StatusNotModified {
		// This status code is possible in the "If-None-Match" case. Don't leave
		// any partial download in progress. Caller should check that responseETag
		// matches ifNoneMatchETag.
		os.Remove(partialFilename)
		os.Remove(partialETagFilename)
		return 0, responseETag, nil
	}

	// Not making failure to write ETag file fatal, in case the entire download
	// succeeds in this one request.
	ioutil.WriteFile(partialETagFilename, []byte(responseETag), 0600)

	// A partial download occurs when this copy is interrupted. The io.Copy
	// will fail, leaving a partial download in place (.part and .part.etag).
	n, err := io.Copy(NewSyncFileWriter(file), response.Body)

	// From this point, n bytes are indicated as downloaded, even if there is
	// an error; the caller may use this to report partial download progress.

	if err != nil {
		return n, "", common.ContextError(err)
	}

	// Ensure the file is flushed to disk. The deferred close
	// will be a noop when this succeeds.
	err = file.Close()
	if err != nil {
		return n, "", common.ContextError(err)
	}

	// Remove if exists, to enable rename
	os.Remove(downloadFilename)

	err = os.Rename(partialFilename, downloadFilename)
	if err != nil {
		return n, "", common.ContextError(err)
	}

	os.Remove(partialETagFilename)

	return n, responseETag, nil
}
