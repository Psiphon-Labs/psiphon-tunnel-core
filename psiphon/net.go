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

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
	utls "github.com/Psiphon-Labs/utls"
	"golang.org/x/net/bpf"
)

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

	// DeviceBinder, when not nil, is applied when dialing UDP/TCP. See:
	// DeviceBinder doc.
	DeviceBinder DeviceBinder

	// IPv6Synthesizer, when not nil, is applied when dialing UDP/TCP. See:
	// IPv6Synthesizer doc.
	IPv6Synthesizer IPv6Synthesizer

	// ResolveIP is used to resolve destination domains. ResolveIP should
	// return either at least one IP address or an error.
	ResolveIP func(context.Context, string) ([]net.IP, error)

	// ResolvedIPCallback, when set, is called with the IP address that was
	// dialed. This is either the specified IP address in the dial address,
	// or the resolved IP address in the case where the dial address is a
	// domain name.
	// The callback may be invoked by a concurrent goroutine.
	ResolvedIPCallback func(string)

	// TrustedCACertificatesFilename specifies a file containing trusted
	// CA certs. See Config.TrustedCACertificatesFilename.
	TrustedCACertificatesFilename string

	// FragmentorConfig specifies whether to layer a fragmentor.Conn on top
	// of dialed TCP conns, and the fragmentation configuration to use.
	FragmentorConfig *fragmentor.Config

	// UpstreamProxyErrorCallback is called when a dial fails due to an upstream
	// proxy error. As the upstream proxy is user configured, the error message
	// may need to be relayed to the user.
	UpstreamProxyErrorCallback func(error)

	// CustomDialer overrides the dialer created by NewNetDialer/NewTCPDialer.
	// When CustomDialer is set, all other DialConfig parameters are ignored by
	// NewNetDialer/NewTCPDialer. Other DialConfig consumers may still reference
	// other DialConfig parameters; for example MeekConfig still uses
	// TrustedCACertificatesFilename.
	CustomDialer common.Dialer
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

// DNSServerGetter defines the interface to the external GetDNSServers provider
// which calls into the host application to discover the native network DNS
// server settings.
type DNSServerGetter interface {
	GetDNSServers() []string
}

// IPv6Synthesizer defines the interface to the external IPv6Synthesize
// provider which calls into the host application to synthesize IPv6 addresses
// from IPv4 ones. This is used to correctly lookup IPs on DNS64/NAT64
// networks.
type IPv6Synthesizer interface {
	IPv6Synthesize(IPv4Addr string) string
}

// HasIPv6RouteGetter defines the interface to the external HasIPv6Route
// provider which calls into the host application to determine if the host
// has an IPv6 route.
type HasIPv6RouteGetter interface {
	// TODO: change to bool return value once gobind supports that type
	HasIPv6Route() int
}

// NetworkIDGetter defines the interface to the external GetNetworkID
// provider, which returns an identifier for the host's current active
// network.
//
// The identifier is a string that indicates the network type and
// identity; for example "WIFI-<BSSID>" or "MOBILE-<MCC/MNC>". As this network
// ID is personally identifying, it is only used locally in the client to
// determine network context and is not sent to the Psiphon server. The
// identifer will be logged in diagnostics messages; in this case only the
// substring before the first "-" is logged, so all PII must appear after the
// first "-".
//
// NetworkIDGetter.GetNetworkID must always return an identifier value, as
// logic that uses GetNetworkID, including tactics, is intended to proceed
// regardless of whether an accurate network identifier can be obtained. The
// the provider shall return "UNKNOWN" when an accurate network
// identifier cannot be obtained. Best-effort is acceptable: e.g., return just
// "WIFI" when only the type of the network but no details can be determined.
//
// The network type is sent to Psiphon servers and logged as
// server_tunnel.network_type. To ensure consistency in stats, all providers
// must use the same network type string values, currently consisting of:
// - "WIFI" for a Wi-Fi network
// - "MOBILE" for a mobile/cellular network
// - "WIRED" for a wired network
// - "VPN" for a VPN network
// - "UNKNOWN" for when the network type cannot be determined
//
// Note that the functions psiphon.GetNetworkType, psiphon.getInproxyNetworkType,
// and inproxy.GetNetworkType must all be updated when new network types are added.
type NetworkIDGetter interface {
	GetNetworkID() string
}

// RefractionNetworkingDialer implements psiphon/common/refraction.Dialer.
type RefractionNetworkingDialer struct {
	config *DialConfig
}

// NewRefractionNetworkingDialer creates a new RefractionNetworkingDialer.
func NewRefractionNetworkingDialer(config *DialConfig) *RefractionNetworkingDialer {
	return &RefractionNetworkingDialer{
		config: config,
	}
}

func (d *RefractionNetworkingDialer) DialContext(
	ctx context.Context,
	network string,
	laddr string,
	raddr string) (net.Conn, error) {

	switch network {
	case "tcp", "tcp4", "tcp6":

		if laddr != "" {
			return nil, errors.TraceNew("unexpected laddr for tcp dial")
		}
		conn, err := DialTCP(ctx, raddr, d.config)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return conn, nil

	case "udp", "udp4", "udp6":

		udpConn, _, err := NewUDPConn(ctx, network, true, laddr, raddr, d.config)
		if err != nil {
			return nil, errors.Trace(err)
		}
		// Ensure blocked packet writes eventually timeout.
		conn := &common.WriteTimeoutUDPConn{
			UDPConn: udpConn,
		}
		return conn, nil

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
func LocalProxyRelay(config *Config, proxyType string, localConn, remoteConn net.Conn) {

	closing := int32(0)

	copyWaitGroup := new(sync.WaitGroup)
	copyWaitGroup.Add(1)

	go func() {
		defer copyWaitGroup.Done()

		_, err := RelayCopyBuffer(config, localConn, remoteConn)
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

	_, err := RelayCopyBuffer(config, remoteConn, localConn)
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

// RelayCopyBuffer performs an io.Copy, optionally using a smaller buffer when
// config.LimitRelayBufferSizes is set.
func RelayCopyBuffer(config *Config, dst io.Writer, src io.Reader) (int64, error) {

	// By default, io.CopyBuffer will allocate a 32K buffer when a nil buffer
	// is passed in. When configured, make and specify a smaller buffer. But
	// only if src doesn't implement WriterTo and dst doesn't implement
	// ReaderFrom, as in those cases io.CopyBuffer entirely avoids a buffer
	// allocation.

	var buffer []byte
	if config.LimitRelayBufferSizes {
		_, isWT := src.(io.WriterTo)
		_, isRF := dst.(io.ReaderFrom)
		if !isWT && !isRF {
			buffer = make([]byte, 4096)
		}
	}

	// Do not wrap any I/O errors
	return io.CopyBuffer(dst, src, buffer)
}

// WaitForNetworkConnectivity uses a NetworkConnectivityChecker to
// periodically check for network connectivity. It returns true if no
// NetworkConnectivityChecker is provided (waiting is disabled) or when
// NetworkConnectivityChecker.HasNetworkConnectivity() indicates
// connectivity. It waits and polls the checker once a second. When
// additionalConditionChecker is not nil, it must also return true for
// WaitForNetworkConnectivity to return true. When the context is done, false
// is returned immediately.
func WaitForNetworkConnectivity(
	ctx context.Context,
	connectivityChecker NetworkConnectivityChecker,
	additionalConditionChecker func() bool) bool {

	if (connectivityChecker == nil || connectivityChecker.HasNetworkConnectivity() == 1) &&
		(additionalConditionChecker == nil || additionalConditionChecker()) {
		return true
	}

	NoticeInfo("waiting for network connectivity")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		if (connectivityChecker == nil || connectivityChecker.HasNetworkConnectivity() == 1) &&
			(additionalConditionChecker == nil || additionalConditionChecker()) {
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

// New Resolver creates a new resolver using the specified config.
// useBindToDevice indicates whether to apply config.BindToDevice, when it
// exists; set useBindToDevice to false when the resolve doesn't need to be
// excluded from any VPN routing.
func NewResolver(config *Config, useBindToDevice bool) *resolver.Resolver {

	p := config.GetParameters().Get()

	networkConfig := &resolver.NetworkConfig{
		LogWarning:                func(err error) { NoticeWarning("ResolveIP: %v", err) },
		LogHostnames:              config.EmitDiagnosticNetworkParameters,
		CacheExtensionInitialTTL:  p.Duration(parameters.DNSResolverCacheExtensionInitialTTL),
		CacheExtensionVerifiedTTL: p.Duration(parameters.DNSResolverCacheExtensionVerifiedTTL),
	}

	if config.DNSServerGetter != nil {
		networkConfig.GetDNSServers = config.DNSServerGetter.GetDNSServers
	}

	if useBindToDevice && config.DeviceBinder != nil {
		networkConfig.BindToDevice = config.DeviceBinder.BindToDevice
		networkConfig.AllowDefaultResolverWithBindToDevice =
			config.AllowDefaultDNSResolverWithBindToDevice
	}

	if config.IPv6Synthesizer != nil {
		networkConfig.IPv6Synthesize = config.IPv6Synthesizer.IPv6Synthesize
	}

	if config.HasIPv6RouteGetter != nil {
		networkConfig.HasIPv6Route = func() bool {
			return config.HasIPv6RouteGetter.HasIPv6Route() == 1
		}
	}

	return resolver.NewResolver(networkConfig, config.GetNetworkID())
}

// UntunneledResolveIP is used to resolve domains for untunneled dials,
// including remote server list and upgrade downloads.
func UntunneledResolveIP(
	ctx context.Context,
	config *Config,
	resolver *resolver.Resolver,
	hostname string,
	frontingProviderID string) ([]net.IP, error) {

	// Limitations: for untunneled resolves, there is currently no resolve
	// parameter replay.

	params, err := resolver.MakeResolveParameters(
		config.GetParameters().Get(), frontingProviderID, hostname)
	if err != nil {
		return nil, errors.Trace(err)
	}

	IPs, err := resolver.ResolveIP(
		ctx,
		config.GetNetworkID(),
		params,
		hostname)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return IPs, nil
}

// makeFrontedHTTPClient returns a net/http.Client which is
// configured to use domain fronting and custom dialing features -- including
// BindToDevice, etc. One or more fronting specs must be provided, i.e.
// len(frontingSpecs) must be greater than 0. A function is returned which,
// if non-nil, can be called after each request made with the net/http.Client
// completes to retrieve the set of API parameter values applied to the request.
//
// The context is applied to underlying TCP dials. The caller is responsible
// for applying the context to requests made with the returned http.Client.
//
// payloadSecure must only be set if all HTTP plaintext payloads sent through
// the returned net/http.Client will be wrapped in their own transport security
// layer, which permits skipping of server certificate verification.
func makeFrontedHTTPClient(
	config *Config,
	tunnel *Tunnel,
	frontingSpecs parameters.FrontingSpecs,
	selectedFrontingProviderID func(string),
	useDeviceBinder,
	skipVerify,
	disableSystemRootCAs,
	payloadSecure bool,
	tlsCache utls.ClientSessionCache) (*http.Client, func() common.APIParameters, error) {

	frontedHTTPClient, err := newFrontedHTTPClientInstance(
		config, tunnel, frontingSpecs, selectedFrontingProviderID,
		useDeviceBinder, skipVerify, disableSystemRootCAs, payloadSecure, tlsCache)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	getParams := func() common.APIParameters {
		return common.APIParameters(frontedHTTPClient.frontedHTTPDialParameters.GetMetrics())
	}

	return &http.Client{
		Transport: common.NewHTTPRoundTripper(frontedHTTPClient.RoundTrip),
	}, getParams, nil
}

// meekHTTPResponseReadCloser wraps an http.Response.Body received over a
// MeekConn in MeekModePlaintextRoundTrip and exposes an io.ReadCloser. Close
// closes the meek conn and response body.
type meekHTTPResponseReadCloser struct {
	conn         *MeekConn
	responseBody io.ReadCloser
}

// newMeekHTTPResponseReadCloser creates a meekHTTPResponseReadCloser.
func newMeekHTTPResponseReadCloser(meekConn *MeekConn, responseBody io.ReadCloser) *meekHTTPResponseReadCloser {
	return &meekHTTPResponseReadCloser{
		conn:         meekConn,
		responseBody: responseBody,
	}
}

// Read implements the io.Reader interface.
func (meek *meekHTTPResponseReadCloser) Read(p []byte) (n int, err error) {
	return meek.responseBody.Read(p)
}

// Read implements the io.Closer interface.
func (meek *meekHTTPResponseReadCloser) Close() error {
	err := meek.responseBody.Close()
	_ = meek.conn.Close()
	return err
}

// MakeUntunneledHTTPClient returns a net/http.Client which is configured to
// use custom dialing features -- including BindToDevice, etc. A function is
// returned which, if non-nil, can be called after each request made with the
// net/http.Client completes to retrieve the set of API parameter values
// applied to the request.
//
// The context is applied to underlying TCP dials. The caller is responsible
// for applying the context to requests made with the returned http.Client.
func MakeUntunneledHTTPClient(
	ctx context.Context,
	config *Config,
	untunneledDialConfig *DialConfig,
	tlsCache utls.ClientSessionCache,
	skipVerify bool,
	disableSystemRootCAs bool,
	payloadSecure bool,
	frontingSpecs parameters.FrontingSpecs,
	frontingUseDeviceBinder bool,
	selectedFrontingProviderID func(string)) (*http.Client, func() common.APIParameters, error) {

	if untunneledDialConfig != nil && len(frontingSpecs) != 0 ||
		untunneledDialConfig == nil && len(frontingSpecs) == 0 {
		return nil, nil, errors.TraceNew("expected either dial configuration or fronting specs")
	}

	if len(frontingSpecs) > 0 {

		// Ignore skipVerify because it only applies when there are no
		// fronting specs.
		httpClient, getParams, err := makeFrontedHTTPClient(
			config,
			nil,
			frontingSpecs,
			selectedFrontingProviderID,
			frontingUseDeviceBinder,
			false,
			disableSystemRootCAs,
			payloadSecure,
			tlsCache,
		)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
		return httpClient, getParams, nil
	}

	dialer := NewTCPDialer(untunneledDialConfig)

	tlsConfig := &CustomTLSConfig{
		Parameters:                    config.GetParameters(),
		Dial:                          dialer,
		UseDialAddrSNI:                true,
		SNIServerName:                 "",
		SkipVerify:                    skipVerify,
		DisableSystemRootCAs:          disableSystemRootCAs,
		TrustedCACertificatesFilename: untunneledDialConfig.TrustedCACertificatesFilename,
		ClientSessionCache:            tlsCache,
	}

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

	return httpClient, nil, nil
}

// MakeTunneledHTTPClient returns a net/http.Client which is
// configured to use custom dialing features including tunneled
// dialing and, optionally, UseTrustedCACertificatesForStockTLS.
// This http.Client uses stock TLS for HTTPS.
func MakeTunneledHTTPClient(
	ctx context.Context,
	config *Config,
	tunnel *Tunnel,
	tlsCache utls.ClientSessionCache,
	skipVerify,
	disableSystemRootCAs,
	payloadSecure bool,
	frontingSpecs parameters.FrontingSpecs,
	selectedFrontingProviderID func(string)) (*http.Client, func() common.APIParameters, error) {

	// Note: there is no dial context since SSH port forward dials cannot
	// be interrupted directly. Closing the tunnel will interrupt the dials.

	if len(frontingSpecs) > 0 {

		// Ignore skipVerify because it only applies when there are no
		// fronting specs.
		httpClient, getParams, err := makeFrontedHTTPClient(
			config,
			tunnel,
			frontingSpecs,
			selectedFrontingProviderID,
			false,
			false,
			disableSystemRootCAs,
			payloadSecure,
			tlsCache)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
		return httpClient, getParams, nil
	}

	tunneledDialer := func(_, addr string) (net.Conn, error) {
		// Set alwaysTunneled to ensure the http.Client traffic is always tunneled,
		// even when split tunnel mode is enabled.
		conn, _, err := tunnel.DialTCPChannel(addr, true, nil)
		return conn, errors.Trace(err)
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
			return nil, nil, errors.Trace(err)
		}
		rootCAs.AppendCertsFromPEM(certData)
		transport.TLSClientConfig = &tls.Config{RootCAs: rootCAs}
	}

	return &http.Client{
		Transport: transport,
	}, nil, nil
}

// MakeDownloadHTTPClient is a helper that sets up a http.Client for use either
// untunneled or through a tunnel. True is returned if the http.Client is setup
// for use through a tunnel; otherwise it is setup for untunneled use. A
// function is returned which, if non-nil, can be called after each request
// made with the http.Client completes to retrieve the set of API
// parameter values applied to the request.
func MakeDownloadHTTPClient(
	ctx context.Context,
	config *Config,
	tunnel *Tunnel,
	untunneledDialConfig *DialConfig,
	tlsCache utls.ClientSessionCache,
	skipVerify,
	disableSystemRootCAs,
	payloadSecure bool,
	frontingSpecs parameters.FrontingSpecs,
	frontingUseDeviceBinder bool,
	selectedFrontingProviderID func(string)) (*http.Client, bool, func() common.APIParameters, error) {

	var httpClient *http.Client
	var getParams func() common.APIParameters
	var err error

	tunneled := tunnel != nil

	if tunneled {

		httpClient, getParams, err = MakeTunneledHTTPClient(
			ctx,
			config,
			tunnel,
			tlsCache,
			skipVerify || disableSystemRootCAs,
			disableSystemRootCAs,
			payloadSecure,
			frontingSpecs,
			selectedFrontingProviderID)
		if err != nil {
			return nil, false, nil, errors.Trace(err)
		}

	} else {

		var dialConfig *DialConfig
		if len(frontingSpecs) == 0 {
			// Must only set DialConfig if there are no fronting specs.
			dialConfig = untunneledDialConfig
		}

		httpClient, getParams, err = MakeUntunneledHTTPClient(
			ctx,
			config,
			dialConfig,
			tlsCache,
			skipVerify,
			disableSystemRootCAs,
			payloadSecure,
			frontingSpecs,
			frontingUseDeviceBinder,
			selectedFrontingProviderID)
		if err != nil {
			return nil, false, nil, errors.Trace(err)
		}
	}

	return httpClient, tunneled, getParams, nil
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
	_ = ioutil.WriteFile(partialETagFilename, []byte(responseETag), 0600)

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
