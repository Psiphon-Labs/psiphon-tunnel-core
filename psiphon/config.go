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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

// TODO: allow all params to be configured

const (
	LEGACY_DATA_STORE_FILENAME                           = "psiphon.db"
	DATA_STORE_FILENAME                                  = "psiphon.boltdb"
	CONNECTION_WORKER_POOL_SIZE                          = 10
	TUNNEL_POOL_SIZE                                     = 1
	TUNNEL_CONNECT_TIMEOUT_SECONDS                       = 20
	TUNNEL_OPERATE_SHUTDOWN_TIMEOUT                      = 1 * time.Second
	TUNNEL_PORT_FORWARD_DIAL_TIMEOUT_SECONDS             = 10
	TUNNEL_SSH_KEEP_ALIVE_PAYLOAD_MAX_BYTES              = 256
	TUNNEL_SSH_KEEP_ALIVE_PERIOD_MIN                     = 60 * time.Second
	TUNNEL_SSH_KEEP_ALIVE_PERIOD_MAX                     = 120 * time.Second
	TUNNEL_SSH_KEEP_ALIVE_PERIODIC_TIMEOUT_SECONDS       = 30
	TUNNEL_SSH_KEEP_ALIVE_PERIODIC_INACTIVE_PERIOD       = 10 * time.Second
	TUNNEL_SSH_KEEP_ALIVE_PROBE_TIMEOUT_SECONDS          = 5
	TUNNEL_SSH_KEEP_ALIVE_PROBE_INACTIVE_PERIOD          = 10 * time.Second
	ESTABLISH_TUNNEL_TIMEOUT_SECONDS                     = 300
	ESTABLISH_TUNNEL_WORK_TIME                           = 60 * time.Second
	ESTABLISH_TUNNEL_PAUSE_PERIOD_SECONDS                = 5
	ESTABLISH_TUNNEL_SERVER_AFFINITY_GRACE_PERIOD        = 1 * time.Second
	HTTP_PROXY_ORIGIN_SERVER_TIMEOUT_SECONDS             = 15
	HTTP_PROXY_MAX_IDLE_CONNECTIONS_PER_HOST             = 50
	FETCH_REMOTE_SERVER_LIST_TIMEOUT_SECONDS             = 30
	FETCH_REMOTE_SERVER_LIST_RETRY_PERIOD_SECONDS        = 30
	FETCH_REMOTE_SERVER_LIST_STALE_PERIOD                = 6 * time.Hour
	PSIPHON_API_SERVER_TIMEOUT_SECONDS                   = 20
	PSIPHON_API_SHUTDOWN_SERVER_TIMEOUT                  = 1 * time.Second
	PSIPHON_API_STATUS_REQUEST_PERIOD_MIN                = 5 * time.Minute
	PSIPHON_API_STATUS_REQUEST_PERIOD_MAX                = 10 * time.Minute
	PSIPHON_API_STATUS_REQUEST_SHORT_PERIOD_MIN          = 5 * time.Second
	PSIPHON_API_STATUS_REQUEST_SHORT_PERIOD_MAX          = 10 * time.Second
	PSIPHON_API_STATUS_REQUEST_PADDING_MAX_BYTES         = 256
	PSIPHON_API_CONNECTED_REQUEST_PERIOD                 = 24 * time.Hour
	PSIPHON_API_CONNECTED_REQUEST_RETRY_PERIOD           = 5 * time.Second
	PSIPHON_API_PERSISTENT_STATS_MAX_COUNT               = 100
	PSIPHON_API_CLIENT_VERIFICATION_REQUEST_RETRY_PERIOD = 5 * time.Second
	PSIPHON_API_CLIENT_VERIFICATION_REQUEST_MAX_RETRIES  = 10
	FETCH_ROUTES_TIMEOUT_SECONDS                         = 60
	DOWNLOAD_UPGRADE_TIMEOUT_SECONDS                     = 60
	DOWNLOAD_UPGRADE_RETRY_PERIOD_SECONDS                = 30
	DOWNLOAD_UPGRADE_STALE_PERIOD                        = 6 * time.Hour
	IMPAIRED_PROTOCOL_CLASSIFICATION_DURATION            = 2 * time.Minute
	IMPAIRED_PROTOCOL_CLASSIFICATION_THRESHOLD           = 3
	TOTAL_BYTES_TRANSFERRED_NOTICE_PERIOD                = 5 * time.Minute
	TRANSFORM_HOST_NAMES_ALWAYS                          = "always"
	TRANSFORM_HOST_NAMES_NEVER                           = "never"
)

// To distinguish omitted timeout params from explicit 0 value timeout
// params, these params are int pointers. nil means no param was supplied
// so use the default; a non-nil pointer to 0 means no timeout.

// Config is the Psiphon configuration specified by the application. This
// configuration controls the behavior of the core tunnel functionality.
type Config struct {
	// LogFilename specifies a file to receive event notices (JSON format)
	// By default, notices are emitted to stdout.
	LogFilename string

	// DataStoreDirectory is the directory in which to store the persistent
	// database, which contains information such as server entries.
	// By default, current working directory.
	//
	// Warning: If the datastore file, DataStoreDirectory/DATA_STORE_FILENAME,
	// exists but fails to open for any reason (checksum error, unexpected file
	// format, etc.) it will be deleted in order to pave a new datastore and
	// continue running.
	DataStoreDirectory string

	// PropagationChannelId is a string identifier which indicates how the
	// Psiphon client was distributed. This parameter is required.
	// This value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary.
	PropagationChannelId string

	// PropagationChannelId is a string identifier which indicates who
	// is sponsoring this Psiphon client. One purpose of this value is to
	// determine the home pages for display. This parameter is required.
	// This value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary.
	SponsorId string

	// RemoteServerListUrl is a URL which specifies a location to fetch
	// out-of-band server entries. This facility is used when a tunnel cannot
	// be established to known servers.
	// This value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary.
	//
	// Deprecated: Use RemoteServerListURLs. When RemoteServerListURLs is
	// not nil, this parameter is ignored.
	RemoteServerListUrl string

	// RemoteServerListURLs is list of URLs which specify locations to fetch
	// out-of-band server entries. This facility is used when a tunnel cannot
	// be established to known servers.
	// This value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary.
	// All URLs must point to the same entity with the same ETag. At least
	// one DownloadURL must have OnlyAfterAttempts = 0.
	RemoteServerListURLs []*DownloadURL

	// RemoteServerListDownloadFilename specifies a target filename for
	// storing the remote server list download. Data is stored in co-located
	// files (RemoteServerListDownloadFilename.part*) to allow for resumable
	// downloading.
	RemoteServerListDownloadFilename string

	// RemoteServerListSignaturePublicKey specifies a public key that's
	// used to authenticate the remote server list payload.
	// This value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary.
	RemoteServerListSignaturePublicKey string

	// ObfuscatedServerListRootURL is a URL which specifies the root location
	// from which to fetch obfuscated server list files.
	// This value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary.
	//
	// Deprecated: Use ObfuscatedServerListRootURLs. When
	// ObfuscatedServerListRootURLs is not nil, this parameter is ignored.
	ObfuscatedServerListRootURL string

	// ObfuscatedServerListRootURLs is a list of URLs which specify root
	// locations from which to fetch obfuscated server list files.
	// This value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary.
	// All URLs must point to the same entity with the same ETag. At least
	// one DownloadURL must have OnlyAfterAttempts = 0.
	ObfuscatedServerListRootURLs []*DownloadURL

	// ObfuscatedServerListDownloadDirectory specifies a target directory for
	// storing the obfuscated remote server list downloads. Data is stored in
	// co-located files (<OSL filename>.part*) to allow for resumable
	// downloading.
	ObfuscatedServerListDownloadDirectory string

	// ClientVersion is the client version number that the client reports
	// to the server. The version number refers to the host client application,
	// not the core tunnel library. One purpose of this value is to enable
	// automatic updates.
	// This value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary.
	// Note that sending a ClientPlatform string which includes "windows"
	// (case insensitive) and a ClientVersion of <= 44 will cause an
	// error in processing the response to DoConnectedRequest calls.
	ClientVersion string

	// ClientPlatform is the client platform ("Windows", "Android", etc.) that
	// the client reports to the server.
	ClientPlatform string

	// TunnelWholeDevice is a flag that is passed through to the handshake
	// request for stats purposes. Set to 1 when the host application is tunneling
	// the whole device, 0 otherwise.
	TunnelWholeDevice int

	// EgressRegion is a ISO 3166-1 alpha-2 country code which indicates which
	// country to egress from. For the default, "", the best performing server
	// in any country is selected.
	EgressRegion string

	// TunnelProtocol indicates which protocol to use. Valid values include:
	// "SSH", "OSSH", "UNFRONTED-MEEK-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH",
	// "UNFRONTED-MEEK-SESSION-TICKET-OSSH", "FRONTED-MEEK-OSSH",
	// "FRONTED-MEEK-HTTP-OSSH".
	// For the default, "", the best performing protocol is used.
	TunnelProtocol string

	// EstablishTunnelTimeoutSeconds specifies a time limit after which to halt
	// the core tunnel controller if no tunnel has been established. The default
	// is ESTABLISH_TUNNEL_TIMEOUT_SECONDS.
	EstablishTunnelTimeoutSeconds *int

	// ListenInterface specifies which interface to listen on.  If no interface
	// is provided then listen on 127.0.0.1.
	// If 'any' is provided then use 0.0.0.0.
	// If there are multiple IP addresses on an interface use the first IPv4 address.
	ListenInterface string

	// DisableLocalSocksProxy disables running the local SOCKS proxy.
	DisableLocalSocksProxy bool

	// LocalSocksProxyPort specifies a port number for the local SOCKS proxy
	// running at 127.0.0.1. For the default value, 0, the system selects a free
	// port (a notice reporting the selected port is emitted).
	LocalSocksProxyPort int

	// LocalHttpProxyPort specifies a port number for the local HTTP proxy
	// running at 127.0.0.1. For the default value, 0, the system selects a free
	// port (a notice reporting the selected port is emitted).
	LocalHttpProxyPort int

	// DisableLocalHTTPProxy disables running the local HTTP proxy.
	DisableLocalHTTPProxy bool

	// ConnectionWorkerPoolSize specifies how many connection attempts to attempt
	// in parallel. The default, 0, uses CONNECTION_WORKER_POOL_SIZE which is
	// recommended.
	ConnectionWorkerPoolSize int

	// TunnelPoolSize specifies how many tunnels to run in parallel. Port forwards
	// are multiplexed over multiple tunnels. The default, 0, uses TUNNEL_POOL_SIZE
	// which is recommended.
	TunnelPoolSize int

	// UpstreamProxyUrl is a URL specifying an upstream proxy to use for all
	// outbound connections. The URL should include proxy type and authentication
	// information, as required. See example URLs here:
	// https://github.com/Psiphon-Labs/psiphon-tunnel-core/tree/master/psiphon/upstreamproxy
	UpstreamProxyUrl string

	// CustomHeaders is a set of additional arbitrary HTTP headers that are
	// added to all plaintext HTTP requests and requests made through an HTTP
	// upstream proxy when specified by UpstreamProxyUrl.
	CustomHeaders http.Header

	// Deprecated: Use CustomHeaders. When CustomHeaders is
	// not nil, this parameter is ignored.
	UpstreamProxyCustomHeaders http.Header

	// NetworkConnectivityChecker is an interface that enables the core tunnel to call
	// into the host application to check for network connectivity. This parameter is
	// only applicable to library deployments.
	NetworkConnectivityChecker NetworkConnectivityChecker

	// DeviceBinder is an interface that enables the core tunnel to call
	// into the host application to bind sockets to specific devices. This is used
	// for VPN routing exclusion. This parameter is only applicable to library
	// deployments.
	DeviceBinder DeviceBinder

	// IPv6Synthesizer is an interface that allows the core tunnel to call
	// into the host application to synthesize IPv6 addresses from IPv4 ones. This
	// is used to correctly lookup IPs on DNS64/NAT64 networks.
	IPv6Synthesizer IPv6Synthesizer

	// DnsServerGetter is an interface that enables the core tunnel to call
	// into the host application to discover the native network DNS server settings.
	// This parameter is only applicable to library deployments.
	DnsServerGetter DnsServerGetter

	// TransformHostNames specifies whether to use hostname transformation circumvention
	// strategies. Set to "always" to always transform, "never" to never transform, and
	// "", the default, for the default transformation strategy.
	TransformHostNames string

	// TargetServerEntry is an encoded server entry. When specified, this server entry
	// is used exclusively and all other known servers are ignored.
	TargetServerEntry string

	// DisableApi disables Psiphon server API calls including handshake, connected,
	// status, etc. This is used for special case temporary tunnels (Windows VPN mode).
	DisableApi bool

	// TargetApiProtocol specifies whether to force use of "ssh" or "web" API protocol.
	// When blank, the default, the optimal API protocol is used. Note that this
	// capability check is not applied before the "CandidateServers" count is emitted.
	// This parameter is intended for testing and debugging only.
	TargetApiProtocol string

	// DisableRemoteServerListFetcher disables fetching remote server lists. This is
	// used for special case temporary tunnels.
	DisableRemoteServerListFetcher bool

	// SplitTunnelRoutesUrlFormat is an URL which specifies the location of a routes
	// file to use for split tunnel mode. The URL must include a placeholder for the
	// client region to be supplied. Split tunnel mode uses the routes file to classify
	// port forward destinations as foreign or domestic and does not tunnel domestic
	// destinations. Split tunnel mode is on when all the SplitTunnel parameters are
	// supplied.
	// This value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary.
	SplitTunnelRoutesUrlFormat string

	// SplitTunnelRoutesSignaturePublicKey specifies a public key that's
	// used to authenticate the split tunnel routes payload.
	// This value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary.
	SplitTunnelRoutesSignaturePublicKey string

	// SplitTunnelDnsServer specifies a DNS server to use when resolving port
	// forward target domain names to IP addresses for classification. The DNS
	// server must support TCP requests.
	SplitTunnelDnsServer string

	// UpgradeDownloadUrl specifies a URL from which to download a host client upgrade
	// file, when one is available. The core tunnel controller provides a resumable
	// download facility which downloads this resource and emits a notice when complete.
	// This value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary.
	//
	// Deprecated: Use UpgradeDownloadURLs. When UpgradeDownloadURLs
	// is not nil, this parameter is ignored.
	UpgradeDownloadUrl string

	// UpgradeDownloadURLs is list of URLs which specify locations from which to
	// download a host client upgrade file, when one is available. The core tunnel
	// controller provides a resumable download facility which downloads this resource
	// and emits a notice when complete.
	// This value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary.
	// All URLs must point to the same entity with the same ETag. At least
	// one DownloadURL must have OnlyAfterAttempts = 0.
	UpgradeDownloadURLs []*DownloadURL

	// UpgradeDownloadClientVersionHeader specifies the HTTP header name for the
	// entity at UpgradeDownloadURLs which specifies the client version (an integer
	// value). A HEAD request may be made to check the version number available at
	// UpgradeDownloadURLs. UpgradeDownloadClientVersionHeader is required when
	// UpgradeDownloadURLs is specified.
	UpgradeDownloadClientVersionHeader string

	// UpgradeDownloadFilename is the local target filename for an upgrade download.
	// This parameter is required when UpgradeDownloadURLs (or UpgradeDownloadUrl)
	// is specified.
	// Data is stored in co-located files (UpgradeDownloadFilename.part*) to allow
	// for resumable downloading.
	UpgradeDownloadFilename string

	// EmitBytesTransferred indicates whether to emit periodic notices showing
	// bytes sent and received.
	EmitBytesTransferred bool

	// UseIndistinguishableTLS enables use of alternative TLS profiles with a less
	// distinct fingerprint (ClientHello content) than the stock Go TLS.
	UseIndistinguishableTLS bool

	// UseTrustedCACertificatesForStockTLS toggles use of the trusted CA certs, specified
	// in TrustedCACertificatesFilename, for tunneled TLS connections that expect
	// server certificates signed with public certificate authorities (currently,
	// only upgrade downloads). This option is used with stock Go TLS in cases where
	// Go may fail to obtain a list of root CAs from the operating system.
	// Requires TrustedCACertificatesFilename to be set.
	UseTrustedCACertificatesForStockTLS bool

	// TrustedCACertificatesFilename specifies a file containing trusted CA certs.
	// The file contents should be compatible with OpenSSL's SSL_CTX_load_verify_locations.
	// When specified, this enables use of OpenSSL for HTTPS requests that require
	// typical (system CA) server authentication.
	TrustedCACertificatesFilename string

	// DisablePeriodicSshKeepAlive indicates whether to send an SSH keepalive every
	// 1-2 minutes, when the tunnel is idle. If the SSH keepalive times out, the tunnel
	// is considered to have failed.
	DisablePeriodicSshKeepAlive bool

	// DeviceRegion is the optional, reported region the host device is running in.
	// This input value should be a ISO 3166-1 alpha-2 country code. The device region
	// is reported to the server in the connected request and recorded for Psiphon
	// stats.
	// When provided, this value may be used, pre-connection, to select performance
	// or circumvention optimization strategies for the given region.
	DeviceRegion string

	// EmitDiagnosticNotices indicates whether to output notices containing detailed
	// information about the Psiphon session. As these notices may contain sensitive
	// network information, they should not be insecurely distributed or displayed
	// to users. Default is off.
	EmitDiagnosticNotices bool

	// TunnelConnectTimeoutSeconds specifies a single tunnel connection sequence timeout.
	// Zero value means that connection process will not time out.
	// If omitted, the default value is TUNNEL_CONNECT_TIMEOUT_SECONDS.
	TunnelConnectTimeoutSeconds *int

	// TunnelPortForwardDialTimeoutSeconds specifies a dial timeout per SSH port forward.
	// Zero value means a port forward dial will not time out.
	// If omitted, the default value is TUNNEL_PORT_FORWARD_DIAL_TIMEOUT_SECONDS.
	TunnelPortForwardDialTimeoutSeconds *int

	// TunnelSshKeepAliveProbeTimeoutSeconds specifies a timeout value for "probe"
	// SSH keep-alive that is sent upon port forward failure.
	// Zero value means keep-alive request will not time out.
	// If omitted, the default value is TUNNEL_SSH_KEEP_ALIVE_PROBE_TIMEOUT_SECONDS.
	TunnelSshKeepAliveProbeTimeoutSeconds *int

	// TunnelSshKeepAlivePeriodicTimeoutSeconds specifies a timeout value for regular
	// SSH keep-alives that are sent periodically.
	// Zero value means keep-alive request will not time out.
	// If omitted, the default value is TUNNEL_SSH_KEEP_ALIVE_PERIODIC_TIMEOUT_SECONDS.
	TunnelSshKeepAlivePeriodicTimeoutSeconds *int

	// FetchRemoteServerListTimeoutSeconds specifies a timeout value for remote server list
	// HTTP requests. Zero value means that request will not time out.
	// If omitted, the default value is FETCH_REMOTE_SERVER_LIST_TIMEOUT_SECONDS.
	FetchRemoteServerListTimeoutSeconds *int

	// PsiphonApiServerTimeoutSeconds specifies a timeout for periodic API HTTP
	// requests to Psiphon server such as stats, home pages, etc.
	// Zero value means that request will not time out.
	// If omitted, the default value is PSIPHON_API_SERVER_TIMEOUT_SECONDS.
	// Note that this value is overridden for final stats requests during shutdown
	// process in order to prevent hangs.
	PsiphonApiServerTimeoutSeconds *int

	// FetchRoutesTimeoutSeconds specifies a timeout value for split tunnel routes
	// HTTP requests. Zero value means that request will not time out.
	// If omitted, the default value is FETCH_ROUTES_TIMEOUT_SECONDS.
	FetchRoutesTimeoutSeconds *int

	// UpgradeDownloadTimeoutSeconds specifies a timeout value for upgrade download
	// HTTP requests. Zero value means that request will not time out.
	// If omitted, the default value is DOWNLOAD_UPGRADE_TIMEOUT_SECONDS.
	DownloadUpgradeTimeoutSeconds *int

	// HttpProxyOriginServerTimeoutSeconds specifies an HTTP response header timeout
	// value in various HTTP relays found in httpProxy.
	// Zero value means that request will not time out.
	// If omitted, the default value is HTTP_PROXY_ORIGIN_SERVER_TIMEOUT_SECONDS.
	HttpProxyOriginServerTimeoutSeconds *int

	// FetchRemoteServerListRetryPeriodSeconds specifies the delay before
	// resuming a remote server list download after a failure.
	// If omitted, the default value FETCH_REMOTE_SERVER_LIST_RETRY_PERIOD_SECONDS.
	FetchRemoteServerListRetryPeriodSeconds *int

	// DownloadUpgradestRetryPeriodSeconds specifies the delay before
	// resuming a client upgrade download after a failure.
	// If omitted, the default value DOWNLOAD_UPGRADE_RETRY_PERIOD_SECONDS.
	DownloadUpgradeRetryPeriodSeconds *int

	// EstablishTunnelPausePeriodSeconds specifies the delay between attempts
	// to establish tunnels. Briefly pausing allows for network conditions to improve
	// and for asynchronous operations such as fetch remote server list to complete.
	// If omitted, the default value is ESTABLISH_TUNNEL_PAUSE_PERIOD_SECONDS.
	EstablishTunnelPausePeriodSeconds *int

	// RateLimits specify throttling configuration for the tunnel.
	RateLimits common.RateLimits

	// EmitSLOKs indicates whether to emit notices for each seeded SLOK. As this
	// could reveal user browsing activity, it's intended for debugging and testing
	// only.
	EmitSLOKs bool

	// PacketTunnelTunDeviceFileDescriptor specifies a tun device file descriptor
	// to use for running a packet tunnel. When this value is > 0, a packet tunnel
	// is established through the server and packets are relayed via the tun device
	// file descriptor. The file descriptor is duped in NewController.
	// When PacketTunnelTunDeviceFileDescriptor is set, TunnelPoolSize must be 1.
	PacketTunnelTunFileDescriptor int

	// LimitedMemoryEnvironment enables memory usage metrics logging, to track
	// memory usage, and selective aggressively garbage collection at high memory
	// pressure phases of operation.
	LimitedMemoryEnvironment bool

	// LimitedMemorySingleConnectionWorkerThreshold limits the number of concurrent
	// connection workers to 1 when the total memory allocation exceeds the specified
	// value.
	// This option is enabled when LimitedMemoryEnvironment is true and when
	// LimitedMemorySingleConnectionWorkerThreshold > 0.
	LimitedMemorySingleConnectionWorkerThreshold int

	// LimitedMemoryStaggerConnectionWorkersMilliseconds adds a specified delay
	// before making each server candidate available to connection workers.
	// This option is enabled when LimitedMemoryEnvironment is true and when
	// LimitedMemorySingleConnectionWorkersThreshold > 0.
	LimitedMemoryStaggerConnectionWorkersMilliseconds int

	// IgnoreHandshakeStatsRegexps skips compiling and using stats regexes.
	IgnoreHandshakeStatsRegexps bool
}

// DownloadURL specifies a URL for downloading resources along with parameters
// for the download strategy.
type DownloadURL struct {

	// URL is the location of the resource. This string is slightly obfuscated
	// with base64 encoding to mitigate trivial binary executable string scanning.
	URL string

	// SkipVerify indicates whether to verify HTTPS certificates. It some
	// circumvention scenarios, verification is not possible. This must
	// only be set to true when the resource has its own verification mechanism.
	SkipVerify bool

	// OnlyAfterAttempts specifies how to schedule this URL when downloading
	// the same resource (same entity, same ETag) from multiple different
	// candidate locations. For a value of N, this URL is only a candidate
	// after N rounds of attempting the download from other URLs.
	OnlyAfterAttempts int
}

// LoadConfig parses and validates a JSON format Psiphon config JSON
// string and returns a Config struct populated with config values.
func LoadConfig(configJson []byte) (*Config, error) {
	var config Config
	err := json.Unmarshal(configJson, &config)
	if err != nil {
		return nil, common.ContextError(err)
	}

	// Do SetEmitDiagnosticNotices first, to ensure config file errors are emitted.
	if config.EmitDiagnosticNotices {
		SetEmitDiagnosticNotices(true)
	}

	// These fields are required; the rest are optional
	if config.PropagationChannelId == "" {
		return nil, common.ContextError(
			errors.New("propagation channel ID is missing from the configuration file"))
	}
	if config.SponsorId == "" {
		return nil, common.ContextError(
			errors.New("sponsor ID is missing from the configuration file"))
	}

	if config.DataStoreDirectory == "" {
		config.DataStoreDirectory, err = os.Getwd()
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	if config.ClientVersion == "" {
		config.ClientVersion = "0"
	}

	_, err = strconv.Atoi(config.ClientVersion)
	if err != nil {
		return nil, common.ContextError(
			fmt.Errorf("invalid client version: %s", err))
	}

	if config.TunnelProtocol != "" {
		if !common.Contains(protocol.SupportedTunnelProtocols, config.TunnelProtocol) {
			return nil, common.ContextError(
				errors.New("invalid tunnel protocol"))
		}
	}

	if config.EstablishTunnelTimeoutSeconds == nil {
		defaultEstablishTunnelTimeoutSeconds := ESTABLISH_TUNNEL_TIMEOUT_SECONDS
		config.EstablishTunnelTimeoutSeconds = &defaultEstablishTunnelTimeoutSeconds
	}

	if config.ConnectionWorkerPoolSize == 0 {
		config.ConnectionWorkerPoolSize = CONNECTION_WORKER_POOL_SIZE
	}

	if config.TunnelPoolSize == 0 {
		config.TunnelPoolSize = TUNNEL_POOL_SIZE
	}

	if config.CustomHeaders == nil {
		// Promote legacy parameter
		config.CustomHeaders = config.UpstreamProxyCustomHeaders
		config.UpstreamProxyCustomHeaders = nil
	}

	if config.NetworkConnectivityChecker != nil {
		return nil, common.ContextError(
			errors.New("NetworkConnectivityChecker interface must be set at runtime"))
	}

	if config.DeviceBinder != nil {
		return nil, common.ContextError(
			errors.New("DeviceBinder interface must be set at runtime"))
	}

	if config.DnsServerGetter != nil {
		return nil, common.ContextError(
			errors.New("DnsServerGetter interface must be set at runtime"))
	}

	if !common.Contains(
		[]string{"", TRANSFORM_HOST_NAMES_ALWAYS, TRANSFORM_HOST_NAMES_NEVER},
		config.TransformHostNames) {

		return nil, common.ContextError(
			errors.New("invalid TransformHostNames"))
	}

	if !common.Contains(
		[]string{"", protocol.PSIPHON_SSH_API_PROTOCOL, protocol.PSIPHON_WEB_API_PROTOCOL},
		config.TargetApiProtocol) {

		return nil, common.ContextError(
			errors.New("invalid TargetApiProtocol"))
	}

	if config.UpgradeDownloadUrl != "" && config.UpgradeDownloadURLs == nil {
		config.UpgradeDownloadURLs = promoteLegacyDownloadURL(config.UpgradeDownloadUrl)
	}

	if config.UpgradeDownloadURLs != nil {

		err := decodeAndValidateDownloadURLs("UpgradeDownloadURLs", config.UpgradeDownloadURLs)
		if err != nil {
			return nil, common.ContextError(err)
		}

		if config.UpgradeDownloadClientVersionHeader == "" {
			return nil, common.ContextError(errors.New("missing UpgradeDownloadClientVersionHeader"))
		}
		if config.UpgradeDownloadFilename == "" {
			return nil, common.ContextError(errors.New("missing UpgradeDownloadFilename"))
		}
	}

	if !config.DisableRemoteServerListFetcher {

		if config.RemoteServerListUrl != "" && config.RemoteServerListURLs == nil {
			config.RemoteServerListURLs = promoteLegacyDownloadURL(config.RemoteServerListUrl)
		}

		if config.RemoteServerListURLs != nil {

			err := decodeAndValidateDownloadURLs("RemoteServerListURLs", config.RemoteServerListURLs)
			if err != nil {
				return nil, common.ContextError(err)
			}

			if config.RemoteServerListSignaturePublicKey == "" {
				return nil, common.ContextError(errors.New("missing RemoteServerListSignaturePublicKey"))
			}

			if config.RemoteServerListDownloadFilename == "" {
				return nil, common.ContextError(errors.New("missing RemoteServerListDownloadFilename"))
			}
		}

		if config.ObfuscatedServerListRootURL != "" && config.ObfuscatedServerListRootURLs == nil {
			config.ObfuscatedServerListRootURLs = promoteLegacyDownloadURL(config.ObfuscatedServerListRootURL)
		}

		if config.ObfuscatedServerListRootURLs != nil {

			err := decodeAndValidateDownloadURLs("ObfuscatedServerListRootURLs", config.ObfuscatedServerListRootURLs)
			if err != nil {
				return nil, common.ContextError(err)
			}

			if config.RemoteServerListSignaturePublicKey == "" {
				return nil, common.ContextError(errors.New("missing RemoteServerListSignaturePublicKey"))
			}

			if config.ObfuscatedServerListDownloadDirectory == "" {
				return nil, common.ContextError(errors.New("missing ObfuscatedServerListDownloadDirectory"))
			}
		}
	}

	// This constraint is expected by logic in Controller.runTunnels()
	if config.PacketTunnelTunFileDescriptor > 0 && config.TunnelPoolSize != 1 {
		return nil, common.ContextError(errors.New("packet tunnel mode requires TunnelPoolSize to be 1"))
	}

	if config.TunnelConnectTimeoutSeconds == nil {
		defaultTunnelConnectTimeoutSeconds := TUNNEL_CONNECT_TIMEOUT_SECONDS
		config.TunnelConnectTimeoutSeconds = &defaultTunnelConnectTimeoutSeconds
	}

	if config.TunnelPortForwardDialTimeoutSeconds == nil {
		TunnelPortForwardDialTimeoutSeconds := TUNNEL_PORT_FORWARD_DIAL_TIMEOUT_SECONDS
		config.TunnelPortForwardDialTimeoutSeconds = &TunnelPortForwardDialTimeoutSeconds
	}

	if config.TunnelSshKeepAliveProbeTimeoutSeconds == nil {
		defaultTunnelSshKeepAliveProbeTimeoutSeconds := TUNNEL_SSH_KEEP_ALIVE_PROBE_TIMEOUT_SECONDS
		config.TunnelSshKeepAliveProbeTimeoutSeconds = &defaultTunnelSshKeepAliveProbeTimeoutSeconds
	}

	if config.TunnelSshKeepAlivePeriodicTimeoutSeconds == nil {
		defaultTunnelSshKeepAlivePeriodicTimeoutSeconds := TUNNEL_SSH_KEEP_ALIVE_PERIODIC_TIMEOUT_SECONDS
		config.TunnelSshKeepAlivePeriodicTimeoutSeconds = &defaultTunnelSshKeepAlivePeriodicTimeoutSeconds
	}

	if config.FetchRemoteServerListTimeoutSeconds == nil {
		defaultFetchRemoteServerListTimeoutSeconds := FETCH_REMOTE_SERVER_LIST_TIMEOUT_SECONDS
		config.FetchRemoteServerListTimeoutSeconds = &defaultFetchRemoteServerListTimeoutSeconds
	}

	if config.PsiphonApiServerTimeoutSeconds == nil {
		defaultPsiphonApiServerTimeoutSeconds := PSIPHON_API_SERVER_TIMEOUT_SECONDS
		config.PsiphonApiServerTimeoutSeconds = &defaultPsiphonApiServerTimeoutSeconds
	}

	if config.FetchRoutesTimeoutSeconds == nil {
		defaultFetchRoutesTimeoutSeconds := FETCH_ROUTES_TIMEOUT_SECONDS
		config.FetchRoutesTimeoutSeconds = &defaultFetchRoutesTimeoutSeconds
	}

	if config.DownloadUpgradeTimeoutSeconds == nil {
		defaultDownloadUpgradeTimeoutSeconds := DOWNLOAD_UPGRADE_TIMEOUT_SECONDS
		config.DownloadUpgradeTimeoutSeconds = &defaultDownloadUpgradeTimeoutSeconds
	}

	if config.HttpProxyOriginServerTimeoutSeconds == nil {
		defaultHttpProxyOriginServerTimeoutSeconds := HTTP_PROXY_ORIGIN_SERVER_TIMEOUT_SECONDS
		config.HttpProxyOriginServerTimeoutSeconds = &defaultHttpProxyOriginServerTimeoutSeconds
	}

	if config.FetchRemoteServerListRetryPeriodSeconds == nil {
		defaultFetchRemoteServerListRetryPeriodSeconds := FETCH_REMOTE_SERVER_LIST_RETRY_PERIOD_SECONDS
		config.FetchRemoteServerListRetryPeriodSeconds = &defaultFetchRemoteServerListRetryPeriodSeconds
	}

	if config.DownloadUpgradeRetryPeriodSeconds == nil {
		defaultDownloadUpgradeRetryPeriodSeconds := DOWNLOAD_UPGRADE_RETRY_PERIOD_SECONDS
		config.DownloadUpgradeRetryPeriodSeconds = &defaultDownloadUpgradeRetryPeriodSeconds
	}

	if config.EstablishTunnelPausePeriodSeconds == nil {
		defaultEstablishTunnelPausePeriodSeconds := ESTABLISH_TUNNEL_PAUSE_PERIOD_SECONDS
		config.EstablishTunnelPausePeriodSeconds = &defaultEstablishTunnelPausePeriodSeconds
	}

	return &config, nil
}

func promoteLegacyDownloadURL(URL string) []*DownloadURL {
	downloadURLs := make([]*DownloadURL, 1)
	downloadURLs[0] = &DownloadURL{
		URL:               base64.StdEncoding.EncodeToString([]byte(URL)),
		SkipVerify:        false,
		OnlyAfterAttempts: 0,
	}
	return downloadURLs
}

func decodeAndValidateDownloadURLs(name string, downloadURLs []*DownloadURL) error {

	hasOnlyAfterZero := false
	for _, downloadURL := range downloadURLs {
		if downloadURL.OnlyAfterAttempts == 0 {
			hasOnlyAfterZero = true
		}
		decodedURL, err := base64.StdEncoding.DecodeString(downloadURL.URL)
		if err != nil {
			return fmt.Errorf("failed to decode URL in %s: %s", name, err)
		}

		downloadURL.URL = string(decodedURL)
	}

	var err error
	if !hasOnlyAfterZero {
		err = fmt.Errorf("must be at least one DownloadURL with OnlyAfterAttempts = 0 in %s", name)
	}

	return err
}

func selectDownloadURL(attempt int, downloadURLs []*DownloadURL) (string, string, bool) {

	// The first OnlyAfterAttempts = 0 URL is the canonical URL. This
	// is the value used as the key for SetUrlETag when multiple download
	// URLs can be used to fetch a single entity.

	canonicalURL := ""
	for _, downloadURL := range downloadURLs {
		if downloadURL.OnlyAfterAttempts == 0 {
			canonicalURL = downloadURL.URL
			break
		}
	}

	candidates := make([]int, 0)
	for index, URL := range downloadURLs {
		if attempt >= URL.OnlyAfterAttempts {
			candidates = append(candidates, index)
		}
	}

	if len(candidates) < 1 {
		// This case is not expected, as decodeAndValidateDownloadURLs
		// should reject configs that would have no candidates for
		// 0 attempts.
		return "", "", true
	}

	selection, err := common.MakeSecureRandomInt(len(candidates))
	if err != nil {
		selection = 0
	}
	downloadURL := downloadURLs[candidates[selection]]

	return downloadURL.URL, canonicalURL, downloadURL.SkipVerify
}
