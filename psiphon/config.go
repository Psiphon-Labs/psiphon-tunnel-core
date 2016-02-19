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
	"encoding/json"
	"errors"
	"os"
	"time"
)

// TODO: allow all params to be configured

const (
	LEGACY_DATA_STORE_FILENAME                     = "psiphon.db"
	DATA_STORE_FILENAME                            = "psiphon.boltdb"
	CONNECTION_WORKER_POOL_SIZE                    = 10
	TUNNEL_POOL_SIZE                               = 1
	TUNNEL_CONNECT_TIMEOUT                         = 20 * time.Second
	TUNNEL_OPERATE_SHUTDOWN_TIMEOUT                = 1 * time.Second
	TUNNEL_PORT_FORWARD_DIAL_TIMEOUT               = 10 * time.Second
	TUNNEL_SSH_KEEP_ALIVE_PAYLOAD_MAX_BYTES        = 256
	TUNNEL_SSH_KEEP_ALIVE_PERIOD_MIN               = 60 * time.Second
	TUNNEL_SSH_KEEP_ALIVE_PERIOD_MAX               = 120 * time.Second
	TUNNEL_SSH_KEEP_ALIVE_PERIODIC_TIMEOUT         = 30 * time.Second
	TUNNEL_SSH_KEEP_ALIVE_PERIODIC_INACTIVE_PERIOD = 10 * time.Second
	TUNNEL_SSH_KEEP_ALIVE_PROBE_TIMEOUT            = 5 * time.Second
	TUNNEL_SSH_KEEP_ALIVE_PROBE_INACTIVE_PERIOD    = 10 * time.Second
	ESTABLISH_TUNNEL_TIMEOUT_SECONDS               = 300
	ESTABLISH_TUNNEL_WORK_TIME                     = 60 * time.Second
	ESTABLISH_TUNNEL_PAUSE_PERIOD                  = 5 * time.Second
	ESTABLISH_TUNNEL_SERVER_AFFINITY_GRACE_PERIOD  = 1 * time.Second
	HTTP_PROXY_ORIGIN_SERVER_TIMEOUT               = 15 * time.Second
	HTTP_PROXY_MAX_IDLE_CONNECTIONS_PER_HOST       = 50
	FETCH_REMOTE_SERVER_LIST_TIMEOUT               = 30 * time.Second
	FETCH_REMOTE_SERVER_LIST_RETRY_PERIOD          = 5 * time.Second
	FETCH_REMOTE_SERVER_LIST_STALE_PERIOD          = 6 * time.Hour
	PSIPHON_API_CLIENT_SESSION_ID_LENGTH           = 16
	PSIPHON_API_SERVER_TIMEOUT                     = 20 * time.Second
	PSIPHON_API_SHUTDOWN_SERVER_TIMEOUT            = 1 * time.Second
	PSIPHON_API_STATUS_REQUEST_PERIOD_MIN          = 5 * time.Minute
	PSIPHON_API_STATUS_REQUEST_PERIOD_MAX          = 10 * time.Minute
	PSIPHON_API_STATUS_REQUEST_SHORT_PERIOD_MIN    = 5 * time.Second
	PSIPHON_API_STATUS_REQUEST_SHORT_PERIOD_MAX    = 10 * time.Second
	PSIPHON_API_STATUS_REQUEST_PADDING_MAX_BYTES   = 256
	PSIPHON_API_CONNECTED_REQUEST_PERIOD           = 24 * time.Hour
	PSIPHON_API_CONNECTED_REQUEST_RETRY_PERIOD     = 5 * time.Second
	PSIPHON_API_TUNNEL_STATS_MAX_COUNT             = 1000
	FETCH_ROUTES_TIMEOUT                           = 1 * time.Minute
	DOWNLOAD_UPGRADE_TIMEOUT                       = 15 * time.Minute
	DOWNLOAD_UPGRADE_RETRY_PAUSE_PERIOD            = 5 * time.Second
	IMPAIRED_PROTOCOL_CLASSIFICATION_DURATION      = 2 * time.Minute
	IMPAIRED_PROTOCOL_CLASSIFICATION_THRESHOLD     = 3
	TOTAL_BYTES_TRANSFERRED_NOTICE_PERIOD          = 5 * time.Minute
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

	// DataStoreTempDirectory is the directory in which to store temporary
	// work files associated with the persistent database.
	// This parameter is deprecated and may be removed.
	DataStoreTempDirectory string

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
	RemoteServerListUrl string

	// RemoteServerListSignaturePublicKey specifies a public key that's
	// used to authenticate the remote server list payload.
	// This value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary.
	RemoteServerListSignaturePublicKey string

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
	// "FRONTED-MEEK-OSSH", "FRONTED-MEEK-HTTP-OSSH". For the default, "",
	// the best performing protocol is used.
	TunnelProtocol string

	// EstablishTunnelTimeoutSeconds specifies a time limit after which to halt
	// the core tunnel controller if no tunnel has been established. By default,
	// the controller will keep trying indefinitely.
	EstablishTunnelTimeoutSeconds *int

	// ListenInterface specifies which interface to listen on.  If no interface
	// is provided then listen on 127.0.0.1.
	// If an invalid interface is provided then listen on localhost (127.0.0.1).
	// If 'any' is provided then use 0.0.0.0.
	// If there are multiple IP addresses on an interface use the first IPv4 address.
	ListenInterface string

	// LocalSocksProxyPort specifies a port number for the local SOCKS proxy
	// running at 127.0.0.1. For the default value, 0, the system selects a free
	// port (a notice reporting the selected port is emitted).
	LocalSocksProxyPort int

	// LocalHttpProxyPort specifies a port number for the local HTTP proxy
	// running at 127.0.0.1. For the default value, 0, the system selects a free
	// port (a notice reporting the selected port is emitted).
	LocalHttpProxyPort int

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

	// NetworkConnectivityChecker is an interface that enables the core tunnel to call
	// into the host application to check for network connectivity. This parameter is
	// only applicable to library deployments.
	NetworkConnectivityChecker NetworkConnectivityChecker

	// DeviceBinder is an interface that enables the core tunnel to call
	// into the host application to bind sockets to specific devices. This is used
	// for VPN routing exclusion. This parameter is only applicable to library
	// deployments.
	DeviceBinder DeviceBinder

	// DnsServerGetter is an interface that enables the core tunnel to call
	// into the host application to discover the native network DNS server settings.
	// This parameter is only applicable to library deployments.
	DnsServerGetter DnsServerGetter

	// TargetServerEntry is an encoded server entry. When specified, this server entry
	// is used exclusively and all other known servers are ignored.
	TargetServerEntry string

	// DisableApi disables Psiphon server API calls including handshake, connected,
	// status, etc. This is used for special case temporary tunnels (Windows VPN mode).
	DisableApi bool

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
	UpgradeDownloadUrl string

	// UpgradeDownloadFilename is the local target filename for an upgrade download.
	// This parameter is required when UpgradeDownloadUrl is specified.
	UpgradeDownloadFilename string

	// EmitBytesTransferred indicates whether to emit periodic notices showing
	// bytes sent and received.
	EmitBytesTransferred bool

	// UseIndistinguishableTLS enables use of an alternative TLS stack with a less
	// distinct fingerprint (ClientHello content) than the stock Go TLS.
	// UseIndistinguishableTLS only applies to untunneled TLS connections. This
	// parameter is only supported on platforms built with OpenSSL.
	// Requires TrustedCACertificatesFilename to be set.
	UseIndistinguishableTLS bool

	// UseTrustedCACertificates toggles use of the trusted CA certs, specified
	// in TrustedCACertificatesFilename, for tunneled TLS connections that expect
	// server certificates signed with public certificate authorities (currently,
	// only upgrade downloads). This option is used with stock Go TLS in cases where
	// Go may fail to obtain a list of root CAs from the operating system.
	// Requires TrustedCACertificatesFilename to be set.
	UseTrustedCACertificatesForStockTLS bool

	// TrustedCACertificatesFilename specifies a file containing trusted CA certs.
	// The file contents should be compatible with OpenSSL's SSL_CTX_load_verify_locations.
	// When specified, this enables use of indistinguishable TLS for HTTPS requests
	// that require typical (system CA) server authentication.
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
	// to users.
	EmitDiagnosticNotices bool
}

// LoadConfig parses and validates a JSON format Psiphon config JSON
// string and returns a Config struct populated with config values.
func LoadConfig(configJson []byte) (*Config, error) {
	var config Config
	err := json.Unmarshal(configJson, &config)
	if err != nil {
		return nil, ContextError(err)
	}

	// These fields are required; the rest are optional
	if config.PropagationChannelId == "" {
		return nil, ContextError(
			errors.New("propagation channel ID is missing from the configuration file"))
	}
	if config.SponsorId == "" {
		return nil, ContextError(
			errors.New("sponsor ID is missing from the configuration file"))
	}

	if config.DataStoreDirectory == "" {
		config.DataStoreDirectory, err = os.Getwd()
		if err != nil {
			return nil, ContextError(err)
		}
	}

	if config.ClientVersion == "" {
		config.ClientVersion = "0"
	}

	if config.TunnelProtocol != "" {
		if !Contains(SupportedTunnelProtocols, config.TunnelProtocol) {
			return nil, ContextError(
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

	if config.NetworkConnectivityChecker != nil {
		return nil, ContextError(errors.New("NetworkConnectivityChecker interface must be set at runtime"))
	}

	if config.DeviceBinder != nil {
		return nil, ContextError(errors.New("DeviceBinder interface must be set at runtime"))
	}

	if config.DnsServerGetter != nil {
		return nil, ContextError(errors.New("DnsServerGetter interface must be set at runtime"))
	}

	if config.EmitDiagnosticNotices {
		setEmitDiagnosticNotices(true)
	}

	return &config, nil
}
