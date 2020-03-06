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
	"context"
	"crypto/tls"
	"crypto/x509"
	std_errors "errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/dns"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"golang.org/x/net/bpf"
)

const DNS_PORT = 53

// DialConfig contains parameters to determine the behavior
// of a Psiphon dialer (TCPDial, UDPDial, MeekDial, etc.)
type DialConfig struct {

	// DiagnosticID is the server ID to record in any diagnostics notices.
	DiagnosticID string

	// UpstreamProxyURL specifies a proxy to connect through.
	// E.g., "http://proxyhost:8080"
	//       "socks5://user:password@proxyhost:1080"
	//       "socks4a://proxyhost:1080"
	//       "http://NTDOMAIN\NTUser:password@proxyhost:3375"
	//
	// Certain tunnel protocols require HTTP CONNECT support
	// when a HTTP proxy is specified. If CONNECT is not
	// supported, those protocols will not connect.
	//
	// UpstreamProxyURL is not used by UDPDial.
	UpstreamProxyURL string

	// CustomHeaders is a set of additional arbitrary HTTP headers that are
	// added to all plaintext HTTP requests and requests made through an HTTP
	// upstream proxy when specified by UpstreamProxyURL.
	CustomHeaders http.Header

	// BPFProgramInstructions specifies a BPF program to attach to the dial
	// socket before connecting.
	BPFProgramInstructions []bpf.RawInstruction

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
	IPv6Synthesizer IPv6Synthesizer

	// TrustedCACertificatesFilename specifies a file containing trusted
	// CA certs. See Config.TrustedCACertificatesFilename.
	TrustedCACertificatesFilename string

	// ResolvedIPCallback, when set, is called with the IP address that was
	// dialed. This is either the specified IP address in the dial address,
	// or the resolved IP address in the case where the dial address is a
	// domain name.
	// The callback may be invoked by a concurrent goroutine.
	ResolvedIPCallback func(string)

	// FragmentorConfig specifies whether to layer a fragmentor.Conn on top
	// of dialed TCP conns, and the fragmentation configuration to use.
	FragmentorConfig *fragmentor.Config
}

// NetworkConnectivityChecker defines the interface to the external
// HasNetworkConnectivity provider, which call into the host application to
// check for network connectivity.
type NetworkConnectivityChecker interface {
	// TODO: change to bool return value once gobind supports that type
	HasNetworkConnectivity() int
}

// DeviceBinder defines the interface to the external BindToDevice provider
// which calls into the host application to bind sockets to specific devices.
// This is used for VPN routing exclusion.
// The string return value should report device information for diagnostics.
type DeviceBinder interface {
	BindToDevice(fileDescriptor int) (string, error)
}

// DnsServerGetter defines the interface to the external GetDnsServer provider
// which calls into the host application to discover the native network DNS
// server settings.
type DnsServerGetter interface {
	GetPrimaryDnsServer() string
	GetSecondaryDnsServer() string
}

// IPv6Synthesizer defines the interface to the external IPv6Synthesize
// provider which calls into the host application to synthesize IPv6 addresses
// from IPv4 ones. This is used to correctly lookup IPs on DNS64/NAT64
// networks.
type IPv6Synthesizer interface {
	IPv6Synthesize(IPv4Addr string) string
}

// NetworkIDGetter defines the interface to the external GetNetworkID
// provider, which returns an identifier for the host's current active
// network.
//
// The identifier is a string that should indicate the network type and
// identity; for example "WIFI-<BSSID>" or "MOBILE-<MCC/MNC>". As this network
// ID is personally identifying, it is only used locally in the client to
// determine network context and is not sent to the Psiphon server. The
// identifer will be logged in diagnostics messages; in this case only the
// substring before the first "-" is logged, so all PII must appear after the
// first "-".
//
// NetworkIDGetter.GetNetworkID should always return an identifier value, as
// logic that uses GetNetworkID, including tactics, is intended to proceed
// regardless of whether an accurate network identifier can be obtained. By
// convention, the provider should return "UNKNOWN" when an accurate network
// identifier cannot be obtained. Best-effort is acceptable: e.g., return just
// "WIFI" when only the type of the network but no details can be determined.
type NetworkIDGetter interface {
	GetNetworkID() string
}

// Dialer is a custom network dialer.
type Dialer func(context.Context, string, string) (net.Conn, error)

// NetDialer implements an interface that matches net.Dialer.
// Limitation: only "tcp" Dials are supported.
type NetDialer struct {
	dialTCP Dialer
}

// NewNetDialer creates a new NetDialer.
func NewNetDialer(config *DialConfig) *NetDialer {
	return &NetDialer{
		dialTCP: NewTCPDialer(config),
	}
}

func (d *NetDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *NetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		return d.dialTCP(ctx, "tcp", address)
	default:
		return nil, errors.Tracef("unsupported network: %s", network)
	}
}

// LocalProxyRelay sends to remoteConn bytes received from localConn,
// and sends to localConn bytes received from remoteConn.
//
// LocalProxyRelay must close localConn in order to interrupt blocking
// I/O calls when the upstream port forward is closed. remoteConn is
// also closed before returning.
func LocalProxyRelay(proxyType string, localConn, remoteConn net.Conn) {

	closing := int32(0)

	copyWaitGroup := new(sync.WaitGroup)
	copyWaitGroup.Add(1)

	go func() {
		defer copyWaitGroup.Done()

		_, err := io.Copy(localConn, remoteConn)
		if err != nil && atomic.LoadInt32(&closing) != 1 {
			NoticeLocalProxyError(proxyType, errors.TraceMsg(err, "Relay failed"))
		}

		// When the server closes a port forward, ex. due to idle timeout,
		// remoteConn.Read will return EOF, which causes the downstream io.Copy to
		// return (with a nil error). To ensure the downstream local proxy
		// connection also closes at this point, we interrupt the blocking upstream
		// io.Copy by closing localConn.

		atomic.StoreInt32(&closing, 1)
		localConn.Close()
	}()

	_, err := io.Copy(remoteConn, localConn)
	if err != nil && atomic.LoadInt32(&closing) != 1 {
		NoticeLocalProxyError(proxyType, errors.TraceMsg(err, "Relay failed"))
	}

	// When a local proxy peer connection closes, localConn.Read will return EOF.
	// As above, close the other end of the relay to ensure immediate shutdown,
	// as no more data can be relayed.

	atomic.StoreInt32(&closing, 1)
	remoteConn.Close()

	copyWaitGroup.Wait()
}

// WaitForNetworkConnectivity uses a NetworkConnectivityChecker to
// periodically check for network connectivity. It returns true if
// no NetworkConnectivityChecker is provided (waiting is disabled)
// or when NetworkConnectivityChecker.HasNetworkConnectivity()
// indicates connectivity. It waits and polls the checker once a second.
// When the context is done, false is returned immediately.
func WaitForNetworkConnectivity(
	ctx context.Context, connectivityChecker NetworkConnectivityChecker) bool {

	if connectivityChecker == nil || connectivityChecker.HasNetworkConnectivity() == 1 {
		return true
	}

	NoticeInfo("waiting for network connectivity")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		if connectivityChecker.HasNetworkConnectivity() == 1 {
			return true
		}

		select {
		case <-ticker.C:
			// Check HasNetworkConnectivity again
		case <-ctx.Done():
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
		return nil, nil, errors.Trace(err)
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

// MakeUntunneledHTTPClient returns a net/http.Client which is configured to
// use custom dialing features -- including BindToDevice, etc. If
// verifyLegacyCertificate is not nil, it's used for certificate verification.
// The context is applied to underlying TCP dials. The caller is responsible
// for applying the context to requests made with the returned http.Client.
func MakeUntunneledHTTPClient(
	ctx context.Context,
	config *Config,
	untunneledDialConfig *DialConfig,
	verifyLegacyCertificate *x509.Certificate,
	skipVerify bool) (*http.Client, error) {

	dialer := NewTCPDialer(untunneledDialConfig)

	// Note: when verifyLegacyCertificate is not nil, some
	// of the other CustomTLSConfig is overridden.
	tlsConfig := &CustomTLSConfig{
		ClientParameters:              config.clientParameters,
		Dial:                          dialer,
		VerifyLegacyCertificate:       verifyLegacyCertificate,
		UseDialAddrSNI:                true,
		SNIServerName:                 "",
		SkipVerify:                    skipVerify,
		TrustedCACertificatesFilename: untunneledDialConfig.TrustedCACertificatesFilename,
	}
	tlsConfig.EnableClientSessionCache()

	tlsDialer := NewCustomTLSDialer(tlsConfig)

	transport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return dialer(ctx, network, addr)
		},
		DialTLS: func(network, addr string) (net.Conn, error) {
			return tlsDialer(ctx, network, addr)
		},
	}

	httpClient := &http.Client{
		Transport: transport,
	}

	return httpClient, nil
}

// MakeTunneledHTTPClient returns a net/http.Client which is
// configured to use custom dialing features including tunneled
// dialing and, optionally, UseTrustedCACertificatesForStockTLS.
// This http.Client uses stock TLS for HTTPS.
func MakeTunneledHTTPClient(
	config *Config,
	tunnel *Tunnel,
	skipVerify bool) (*http.Client, error) {

	// Note: there is no dial context since SSH port forward dials cannot
	// be interrupted directly. Closing the tunnel will interrupt the dials.

	tunneledDialer := func(_, addr string) (conn net.Conn, err error) {
		return tunnel.sshClient.Dial("tcp", addr)
	}

	transport := &http.Transport{
		Dial: tunneledDialer,
	}

	if skipVerify {

		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	} else if config.TrustedCACertificatesFilename != "" {

		rootCAs := x509.NewCertPool()
		certData, err := ioutil.ReadFile(config.TrustedCACertificatesFilename)
		if err != nil {
			return nil, errors.Trace(err)
		}
		rootCAs.AppendCertsFromPEM(certData)
		transport.TLSClientConfig = &tls.Config{RootCAs: rootCAs}
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

// MakeDownloadHTTPClient is a helper that sets up a http.Client
// for use either untunneled or through a tunnel.
func MakeDownloadHTTPClient(
	ctx context.Context,
	config *Config,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig,
	skipVerify bool) (*http.Client, bool, error) {

	var httpClient *http.Client
	var err error

	tunneled := tunnel != nil

	if tunneled {

		httpClient, err = MakeTunneledHTTPClient(
			config, tunnel, skipVerify)
		if err != nil {
			return nil, false, errors.Trace(err)
		}

	} else {

		httpClient, err = MakeUntunneledHTTPClient(
			ctx, config, untunneledDialConfig, nil, skipVerify)
		if err != nil {
			return nil, false, errors.Trace(err)
		}
	}

	return httpClient, tunneled, nil
}

// ResumeDownload is a reusable helper that downloads requestUrl via the
// httpClient, storing the result in downloadFilename when the download is
// complete. Intermediate, partial downloads state is stored in
// downloadFilename.part and downloadFilename.part.etag.
// Any existing downloadFilename file will be overwritten.
//
// In the case where the remote object has changed while a partial download
// is to be resumed, the partial state is reset and resumeDownload fails.
// The caller must restart the download.
//
// When ifNoneMatchETag is specified, no download is made if the remote
// object has the same ETag. ifNoneMatchETag has an effect only when no
// partial download is in progress.
//
func ResumeDownload(
	ctx context.Context,
	httpClient *http.Client,
	downloadURL string,
	userAgent string,
	downloadFilename string,
	ifNoneMatchETag string) (int64, string, error) {

	partialFilename := fmt.Sprintf("%s.part", downloadFilename)

	partialETagFilename := fmt.Sprintf("%s.part.etag", downloadFilename)

	file, err := os.OpenFile(partialFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return 0, "", errors.Trace(err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return 0, "", errors.Trace(err)
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

			// On Windows, file must be closed before it can be deleted
			file.Close()

			tempErr := os.Remove(partialFilename)
			if tempErr != nil && !os.IsNotExist(tempErr) {
				NoticeWarning("reset partial download failed: %s", tempErr)
			}

			tempErr = os.Remove(partialETagFilename)
			if tempErr != nil && !os.IsNotExist(tempErr) {
				NoticeWarning("reset partial download ETag failed: %s", tempErr)
			}

			return 0, "", errors.Tracef(
				"failed to load partial download ETag: %s", err)
		}
	}

	request, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return 0, "", errors.Trace(err)
	}

	request = request.WithContext(ctx)

	request.Header.Set("User-Agent", userAgent)

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

			// Certain http servers return 200 OK where we expect 206, so accept that.
			response.StatusCode != http.StatusOK &&

			response.StatusCode != http.StatusRequestedRangeNotSatisfiable &&
			response.StatusCode != http.StatusPreconditionFailed &&
			response.StatusCode != http.StatusNotModified) {
		response.Body.Close()
		err = fmt.Errorf("unexpected response status code: %d", response.StatusCode)
	}
	if err != nil {

		// Redact URL from "net/http" error message.
		if !GetEmitNetworkParameters() {
			errStr := err.Error()
			err = std_errors.New(strings.Replace(errStr, downloadURL, "[redacted]", -1))
		}

		return 0, "", errors.Trace(err)
	}
	defer response.Body.Close()

	responseETag := response.Header.Get("ETag")

	if response.StatusCode == http.StatusPreconditionFailed {
		// When the ETag no longer matches, delete the partial download. As above,
		// simply failing and relying on the caller's retry schedule.
		os.Remove(partialFilename)
		os.Remove(partialETagFilename)
		return 0, "", errors.TraceNew("partial download ETag mismatch")

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
		return n, "", errors.Trace(err)
	}

	// Ensure the file is flushed to disk. The deferred close
	// will be a noop when this succeeds.
	err = file.Close()
	if err != nil {
		return n, "", errors.Trace(err)
	}

	// Remove if exists, to enable rename
	os.Remove(downloadFilename)

	err = os.Rename(partialFilename, downloadFilename)
	if err != nil {
		return n, "", errors.Trace(err)
	}

	os.Remove(partialETagFilename)

	return n, responseETag, nil
}
