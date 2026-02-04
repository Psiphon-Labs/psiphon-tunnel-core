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
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/networkid"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	TUNNEL_POOL_SIZE     = 1
	MAX_TUNNEL_POOL_SIZE = 32

	// Psiphon data directory name, relative to config.DataRootDirectory.
	// See config.GetPsiphonDataDirectory().
	PsiphonDataDirectoryName = "ca.psiphon.PsiphonTunnel.tunnel-core"

	// Filename constants, all relative to config.GetPsiphonDataDirectory().
	HomepageFilename        = "homepage"
	NoticesFilename         = "notices"
	OldNoticesFilename      = "notices.1"
	UpgradeDownloadFilename = "upgrade"
)

// Config is the Psiphon configuration specified by the application. This
// configuration controls the behavior of the core tunnel functionality.
//
// To distinguish omitted timeout params from explicit 0 value timeout params,
// corresponding fields are int pointers. nil means no value was supplied and
// to use the default; a non-nil pointer to 0 means no timeout.
type Config struct {

	// DataRootDirectory is the directory in which to store persistent files,
	// which contain information such as server entries. By default, current
	// working directory.
	//
	// Psiphon will assume full control of files under this directory. They may
	// be deleted, moved or overwritten.
	DataRootDirectory string `json:",omitempty"`

	// UseNoticeFiles configures notice files for writing. If set, homepages
	// will be written to a file created at config.GetHomePageFilename()
	// and notices will be written to a file created at
	// config.GetNoticesFilename().
	//
	// The homepage file may be read after the Tunnels notice with count of 1.
	//
	// The value of UseNoticeFiles sets the size and frequency at which the
	// notices file, config.GetNoticesFilename(), will be rotated. See the
	// comment for UseNoticeFiles for more details. One rotated older file,
	// config.GetOldNoticesFilename(), is retained.
	//
	// The notice files may be may be read at any time; and should be opened
	// read-only for reading. Diagnostic notices are omitted from the notice
	// files.
	//
	// See comment for setNoticeFiles in notice.go for further details.
	UseNoticeFiles *UseNoticeFiles `json:",omitempty"`

	// PropagationChannelId is a string identifier which indicates how the
	// Psiphon client was distributed. This parameter is required. This value
	// is supplied by and depends on the Psiphon Network, and is typically
	// embedded in the client binary.
	PropagationChannelId string `json:",omitempty"`

	// SponsorId is a string identifier which indicates who is sponsoring this
	// Psiphon client. One purpose of this value is to determine the home
	// pages for display. This parameter is required. This value is supplied
	// by and depends on the Psiphon Network, and is typically embedded in the
	// client binary.
	SponsorId string `json:",omitempty"`

	// ClientVersion is the client version number that the client reports to
	// the server. The version number refers to the host client application,
	// not the core tunnel library. One purpose of this value is to enable
	// automatic updates. This value is supplied by and depends on the Psiphon
	// Network, and is typically embedded in the client binary.
	//
	// Note that sending a ClientPlatform string which includes "windows"
	// (case insensitive) and a ClientVersion of <= 44 will cause an error in
	// processing the response to DoConnectedRequest calls.
	ClientVersion string `json:",omitempty"`

	// ClientPlatform is the client platform ("Windows", "Android", etc.) that
	// the client reports to the server.
	ClientPlatform string `json:",omitempty"`

	// ClientAPILevel is the client API or SDK level, such as
	// Build.VERSION.SDK_INT on Android. This value is used for local
	// configuration, as required, and not reported to the server.
	// ClientAPILevel is ignored when 0.
	ClientAPILevel int `json:",omitempty"`

	// ClientFeatures is a list of feature names denoting enabled application
	// features. Clients report enabled features to the server for stats
	// purposes.
	ClientFeatures []string `json:",omitempty"`

	// EgressRegion is a ISO 3166-1 alpha-2 country code which indicates which
	// country to egress from. For the default, "", the best performing server
	// in any country is selected.
	EgressRegion string `json:",omitempty"`

	// SplitTunnelOwnRegion enables split tunnel mode for the client's own
	// country. When enabled, TCP port forward destinations that resolve to
	// the same GeoIP country as the client are connected to directly,
	// untunneled.
	SplitTunnelOwnRegion bool `json:",omitempty"`

	// SplitTunnelRegions enables selected split tunnel mode in which the
	// client specifies a list of ISO 3166-1 alpha-2 country codes for which
	// traffic should be untunneled. TCP port forwards destined to any
	// country specified in SplitTunnelRegions will be untunneled, regardless
	// of whether SplitTunnelOwnRegion is on or off.
	SplitTunnelRegions []string `json:",omitempty"`

	// ListenInterface specifies which interface to listen on.  If no
	// interface is provided then listen on 127.0.0.1. If 'any' is provided
	// then use 0.0.0.0. If there are multiple IP addresses on an interface
	// use the first IPv4 address.
	ListenInterface string `json:",omitempty"`

	// DisableLocalSocksProxy disables running the local SOCKS proxy.
	DisableLocalSocksProxy bool `json:",omitempty"`

	// LocalSocksProxyPort specifies a port number for the local SOCKS proxy
	// running at 127.0.0.1. For the default value, 0, the system selects a
	// free port (a notice reporting the selected port is emitted).
	LocalSocksProxyPort int `json:",omitempty"`

	// LocalHttpProxyPort specifies a port number for the local HTTP proxy
	// running at 127.0.0.1. For the default value, 0, the system selects a
	// free port (a notice reporting the selected port is emitted).
	LocalHttpProxyPort int `json:",omitempty"`

	// DisableLocalHTTPProxy disables running the local HTTP proxy.
	DisableLocalHTTPProxy bool `json:",omitempty"`

	// NetworkLatencyMultiplier is a multiplier that is to be applied to
	// default network event timeouts. Set this to tune performance for
	// slow networks.
	// When set, must be >= 1.0.
	NetworkLatencyMultiplier float64 `json:",omitempty"`

	// LimitTunnelProtocols indicates which protocols to use. Valid values
	// include: "SSH", "OSSH", "TLS-OSSH", "UNFRONTED-MEEK-OSSH",
	// "UNFRONTED-MEEK-HTTPS-OSSH", "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
	// "FRONTED-MEEK-OSSH", "FRONTED-MEEK-HTTP-OSSH", "QUIC-OSSH",
	// "FRONTED-MEEK-QUIC-OSSH", "TAPDANCE-OSSH", "CONJURE-OSSH", and
	// "SHADOWSOCKS-OSSH".
	// For the default, an empty list, all protocols are used.
	LimitTunnelProtocols []string `json:",omitempty"`

	// InitialLimitTunnelProtocols is an optional initial phase of limited
	// protocols for the first InitialLimitTunnelProtocolsCandidateCount
	// candidates; after these candidates, LimitTunnelProtocols applies.
	//
	// For the default, an empty list, InitialLimitTunnelProtocols is off.
	InitialLimitTunnelProtocols []string `json:",omitempty"`

	// InitialLimitTunnelProtocolsCandidateCount is the number of candidates
	// to which InitialLimitTunnelProtocols is applied instead of
	// LimitTunnelProtocols.
	//
	// For the default, 0, InitialLimitTunnelProtocols is off.
	InitialLimitTunnelProtocolsCandidateCount int `json:",omitempty"`

	// LimitTLSProfiles indicates which TLS profiles to select from. Valid
	// values are listed in protocols.SupportedTLSProfiles.
	// For the default, an empty list, all profiles are candidates for
	// selection.
	LimitTLSProfiles []string `json:",omitempty"`

	// LimitQUICVersions indicates which QUIC versions to select from. Valid
	// values are listed in protocols.SupportedQUICVersions.
	// For the default, an empty list, all versions are candidates for
	// selection.
	LimitQUICVersions []string `json:",omitempty"`

	// EstablishTunnelTimeoutSeconds specifies a time limit after which to
	// halt the core tunnel controller if no tunnel has been established. The
	// default is parameters.EstablishTunnelTimeout.
	EstablishTunnelTimeoutSeconds *int `json:",omitempty"`

	// EstablishTunnelPausePeriodSeconds specifies the delay between attempts
	// to establish tunnels. Briefly pausing allows for network conditions to
	// improve and for asynchronous operations such as fetch remote server
	// list to complete. If omitted, a default value is used. This value is
	// typical overridden for testing.
	EstablishTunnelPausePeriodSeconds *int `json:",omitempty"`

	// EstablishTunnelPausePeriodSeconds specifies the grace period, or head
	// start, provided to the affinity server candidate when establishing. The
	// affinity server is the server used for the last established tunnel.
	EstablishTunnelServerAffinityGracePeriodMilliseconds *int `json:",omitempty"`

	// ConnectionWorkerPoolSize specifies how many connection attempts to
	// attempt in parallel. If omitted or when 0, a default is used; this is
	// recommended.
	ConnectionWorkerPoolSize int `json:",omitempty"`

	// ConnectionWorkerPoolMaxSize specifies a cap for ConnectionWorkerPoolSize
	// that will not be exceeded by any tactics setting. This is intended for
	// use in low memory environments. If omitted or when 0, it has no effect.
	ConnectionWorkerPoolMaxSize int `json:",omitempty"`

	// DisableConnectionWorkerPool forces ConnectionWorkerPoolSize to 0; this
	// may be used to load cached tactics or perform an untunneled tactics
	// request and then post tactics-related notices, including Application
	// Parameters, without establishing a tunnel. When
	// DisableConnectionWorkerPool is set, server list bootstrapping remains
	// enabled.
	DisableConnectionWorkerPool bool `json:",omitempty"`

	// TunnelPoolSize specifies how many tunnels to run in parallel. Port
	// forwards are multiplexed over multiple tunnels. If omitted or when 0,
	// the default is TUNNEL_POOL_SIZE, which is recommended. Any value over
	// MAX_TUNNEL_POOL_SIZE is treated as MAX_TUNNEL_POOL_SIZE.
	TunnelPoolSize int `json:",omitempty"`

	// StaggerConnectionWorkersMilliseconds adds a specified delay before
	// making each server candidate available to connection workers. This
	// option is enabled when StaggerConnectionWorkersMilliseconds > 0.
	StaggerConnectionWorkersMilliseconds int `json:",omitempty"`

	// LimitIntensiveConnectionWorkers limits the number of concurrent
	// connection workers attempting connections with resource intensive
	// protocols. This option is enabled when LimitIntensiveConnectionWorkers
	// > 0.
	LimitIntensiveConnectionWorkers int `json:",omitempty"`

	// LimitMeekBufferSizes selects smaller buffers for meek protocols.
	LimitMeekBufferSizes bool `json:",omitempty"`

	// LimitCPUThreads minimizes the number of CPU threads -- and associated
	// overhead -- the are used.
	LimitCPUThreads bool `json:",omitempty"`

	// LimitRelayBufferSizes selects smaller buffers for port forward relaying.
	LimitRelayBufferSizes bool `json:",omitempty"`

	// IgnoreHandshakeStatsRegexps skips compiling and using stats regexes.
	IgnoreHandshakeStatsRegexps bool `json:",omitempty"`

	// UpstreamProxyURL is a URL specifying an upstream proxy to use for all
	// outbound connections. The URL should include proxy type and
	// authentication information, as required. See example URLs here:
	// https://github.com/Psiphon-Labs/psiphon-tunnel-core/tree/master/psiphon/upstreamproxy
	UpstreamProxyURL string `json:",omitempty"`

	// CustomHeaders is a set of additional arbitrary HTTP headers that are
	// added to all plaintext HTTP requests and requests made through an HTTP
	// upstream proxy when specified by UpstreamProxyURL.
	CustomHeaders http.Header `json:",omitempty"`

	// MeekAdditionalHeaders is a set of additional arbitrary HTTP headers
	// that are added to all meek HTTP requests. An additional header is
	// ignored when the header name is already present in a meek request.
	MeekAdditionalHeaders http.Header `json:",omitempty"`

	// NetworkConnectivityChecker is an interface that enables tunnel-core to
	// call into the host application to check for network connectivity. See:
	// NetworkConnectivityChecker doc.
	NetworkConnectivityChecker NetworkConnectivityChecker `json:",omitempty"`

	// DeviceBinder is an interface that enables tunnel-core to call into the
	// host application to bind sockets to specific devices. See: DeviceBinder
	// doc.
	//
	// When DeviceBinder is set, the "VPN" feature name is automatically added
	// when reporting ClientFeatures.
	DeviceBinder DeviceBinder `json:",omitempty"`

	// AllowDefaultDNSResolverWithBindToDevice indicates that it's safe to use
	// the default resolver when DeviceBinder is configured, as the host OS
	// will automatically exclude DNS requests from the VPN.
	AllowDefaultDNSResolverWithBindToDevice bool `json:",omitempty"`

	// IPv6Synthesizer is an interface that allows tunnel-core to call into
	// the host application to synthesize IPv6 addresses. See: IPv6Synthesizer
	// doc.
	IPv6Synthesizer IPv6Synthesizer `json:",omitempty"`

	// HasIPv6RouteGetter is an interface that allows tunnel-core to call into
	// the host application to determine if the host has an IPv6 route. See:
	// HasIPv6RouteGetter doc.
	HasIPv6RouteGetter HasIPv6RouteGetter `json:",omitempty"`

	// DNSServerGetter is an interface that enables tunnel-core to call into
	// the host application to discover the native network DNS server
	// settings. See: DNSServerGetter doc.
	DNSServerGetter DNSServerGetter `json:",omitempty"`

	// NetworkIDGetter in an interface that enables tunnel-core to call into
	// the host application to get an identifier for the host's current active
	// network. See: NetworkIDGetter doc.
	NetworkIDGetter NetworkIDGetter `json:",omitempty"`

	// NetworkID, when not blank, is used as the identifier for the host's
	// current active network.
	// NetworkID is ignored when NetworkIDGetter is set, or when
	// common/networkid is enabled.
	NetworkID string `json:",omitempty"`

	// DisableTactics disables tactics operations including requests, payload
	// handling, and application of parameters.
	DisableTactics bool `json:",omitempty"`

	// DisableReplay causes any persisted dial parameters to be ignored when
	// they would otherwise be used for replay.
	DisableReplay bool `json:",omitempty"`

	// TargetServerEntry is an encoded server entry. When specified, this
	// server entry is used exclusively and all other known servers are
	// ignored; also, when set, ConnectionWorkerPoolSize is ignored and
	// the pool size is 1.
	TargetServerEntry string `json:",omitempty"`

	// DisableApi disables Psiphon server API calls including handshake,
	// connected, status, etc. This is used for special case temporary tunnels
	// (Windows VPN mode).
	DisableApi bool `json:",omitempty"`

	// TargetAPIProtocol specifies whether to force use of "ssh" or "web" API
	// protocol. When blank, the default, the optimal API protocol is used.
	// Note that this capability check is not applied before the
	// "CandidateServers" count is emitted.
	//
	// This parameter is intended for testing and debugging only. Not all
	// parameters are supported in the legacy "web" API protocol, including
	// speed test samples.
	TargetAPIProtocol string `json:",omitempty"`

	// TargetAPIProtocol specifies whether to use "json" or "cbor" API
	// protocol parameter encodings. When blank, the default is to use "cbor"
	// where supported.
	TargetAPIEncoding string `json:",omitempty"`

	// RemoteServerListURLs is list of URLs which specify locations to fetch
	// out-of-band server entries. This facility is used when a tunnel cannot
	// be established to known servers. This value is supplied by and depends
	// on the Psiphon Network, and is typically embedded in the client binary.
	// All URLs must point to the same entity with the same ETag. At least one
	// TransferURL must have OnlyAfterAttempts = 0.
	RemoteServerListURLs parameters.TransferURLs `json:",omitempty"`

	// RemoteServerListSignaturePublicKey specifies a public key that's used
	// to authenticate the remote server list payload. This value is supplied
	// by and depends on the Psiphon Network, and is typically embedded in the
	// client binary.
	RemoteServerListSignaturePublicKey string `json:",omitempty"`

	// DisableRemoteServerListFetcher disables fetching remote server lists.
	// This is used for special case temporary tunnels.
	DisableRemoteServerListFetcher bool `json:",omitempty"`

	// FetchRemoteServerListRetryPeriodMilliseconds specifies the delay before
	// resuming a remote server list download after a failure. If omitted, a
	// default value is used. This value is typical overridden for testing.
	FetchRemoteServerListRetryPeriodMilliseconds *int `json:",omitempty"`

	// ObfuscatedServerListRootURLs is a list of URLs which specify root
	// locations from which to fetch obfuscated server list files. This value
	// is supplied by and depends on the Psiphon Network, and is typically
	// embedded in the client binary. All URLs must point to the same entity
	// with the same ETag. At least one DownloadURL must have
	// OnlyAfterAttempts = 0.
	ObfuscatedServerListRootURLs parameters.TransferURLs `json:",omitempty"`

	// EnableUpgradeDownload indicates whether to check for and download
	// upgrades. When set, UpgradeDownloadURLs and
	// UpgradeDownloadClientVersionHeader must also be set. ClientPlatform
	// and ClientVersion should also be set.
	EnableUpgradeDownload bool `json:",omitempty"`

	// UpgradeDownloadURLs is list of URLs which specify locations from which
	// to download a host client upgrade file, when one is available. The core
	// tunnel controller provides a resumable download facility which
	// downloads this resource and emits a notice when complete. This value is
	// supplied by and depends on the Psiphon Network, and is typically
	// embedded in the client binary. All URLs must point to the same entity
	// with the same ETag. At least one DownloadURL must have
	// OnlyAfterAttempts = 0.
	UpgradeDownloadURLs parameters.TransferURLs `json:",omitempty"`

	// UpgradeDownloadClientVersionHeader specifies the HTTP header name for
	// the entity at UpgradeDownloadURLs which specifies the client version
	// (an integer value). A HEAD request may be made to check the version
	// number available at UpgradeDownloadURLs.
	// UpgradeDownloadClientVersionHeader is required when UpgradeDownloadURLs
	// is specified.
	UpgradeDownloadClientVersionHeader string `json:",omitempty"`

	// FetchUpgradeRetryPeriodMilliseconds specifies the delay before resuming
	// a client upgrade download after a failure. If omitted, a default value
	// is used. This value is typical overridden for testing.
	FetchUpgradeRetryPeriodMilliseconds *int `json:",omitempty"`

	// EnableFeedbackUpload indicates whether to enable uploading feedback
	// data. When set, FeedbackUploadURLs and FeedbackEncryptionPublicKey
	// must also be set.
	EnableFeedbackUpload bool `json:",omitempty"`

	// FeedbackUploadURLs is a list of SecureTransferURLs which specify
	// locations where feedback data can be uploaded, pairing with each
	// location a public key with which to encrypt the feedback data. This
	// value is supplied by and depends on the Psiphon Network, and is
	// typically embedded in the client binary. At least one TransferURL must
	// have OnlyAfterAttempts = 0.
	FeedbackUploadURLs parameters.TransferURLs `json:",omitempty"`

	// FeedbackEncryptionPublicKey is a default base64-encoded, RSA public key
	// value used to encrypt feedback data. Used when uploading feedback with a
	// TransferURL which has no public key value configured, i.e.
	// B64EncodedPublicKey = "".
	FeedbackEncryptionPublicKey string `json:",omitempty"`

	// TrustedCACertificatesFilename specifies a file containing trusted CA
	// certs. When set, this toggles use of the trusted CA certs, specified in
	// TrustedCACertificatesFilename, for tunneled TLS connections that expect
	// server certificates signed with public certificate authorities
	// (currently, only upgrade downloads). This option is used with stock Go
	// TLS in cases where Go may fail to obtain a list of root CAs from the
	// operating system.
	TrustedCACertificatesFilename string `json:",omitempty"`

	// DisableSystemRootCAs, when true, disables loading system root CAs when
	// verifying TLS certificates for all remote server list downloads, upgrade
	// downloads, and feedback uploads. Each of these transfers has additional
	// security at the payload level. Verifying TLS certificates is preferred,
	// as an additional security and circumvention layer; set
	// DisableSystemRootCAs only in cases where system root CAs cannot be
	// loaded; for example, if unsupported (iOS < 12) or insufficient memory
	// (VPN extension on iOS < 15).
	DisableSystemRootCAs bool `json:",omitempty"`

	// DisablePeriodicSshKeepAlive indicates whether to send an SSH keepalive
	// every 1-2 minutes, when the tunnel is idle. If the SSH keepalive times
	// out, the tunnel is considered to have failed.
	DisablePeriodicSshKeepAlive bool `json:",omitempty"`

	// DeviceLocation is the optional, reported location the host device is
	// running in. This input value should be a string representing location
	// geohash. The device location is reported to the server in the connected
	// request and recorded for Psiphon stats.
	DeviceLocation string `json:",omitempty"`

	// DeviceRegion is the optional, reported region the host device is
	// running in. This input value should be a ISO 3166-1 alpha-2 country
	// code. The device region is reported to the server in the connected
	// request and recorded for Psiphon stats.
	//
	// When provided, this value may be used, pre-connection, to select
	// performance or circumvention optimization strategies for the given
	// region.
	DeviceRegion string `json:",omitempty"`

	// EmitDiagnosticNotices indicates whether to output notices containing
	// detailed information about the Psiphon session. As these notices may
	// contain sensitive information, they should not be insecurely distributed
	// or displayed to users. Default is off.
	EmitDiagnosticNotices bool `json:",omitempty"`

	// EmitDiagnosticNetworkParameters indicates whether to include network
	// parameters in diagnostic notices. As these parameters are sensitive
	// circumvention network information, they should not be insecurely
	// distributed or displayed to users. Default is off.
	EmitDiagnosticNetworkParameters bool `json:",omitempty"`

	// EmitBytesTransferred indicates whether to emit frequent notices showing
	// bytes sent and received.
	EmitBytesTransferred bool `json:",omitempty"`

	// EmitSLOKs indicates whether to emit notices for each seeded SLOK. As
	// this could reveal user browsing activity, it's intended for debugging
	// and testing only.
	EmitSLOKs bool `json:",omitempty"`

	// EmitRefractionNetworkingLogs indicates whether to emit gotapdance log
	// messages to stdout. Note that gotapdance log messages do not conform to
	// the Notice format standard. Default is off.
	EmitRefractionNetworkingLogs bool `json:",omitempty"`

	// EmitServerAlerts indicates whether to emit notices for server alerts.
	EmitServerAlerts bool `json:",omitempty"`

	// EmitClientAddress indicates whether to emit the client's public network
	// address, IP and port, as seen by the server. For non-direct protocols,
	// such as FRONTED and INPROXY, where the client isn't connecting
	// directly to the server, the reported port number is 0.
	EmitClientAddress bool `json:",omitempty"`

	// RateLimits specify throttling configuration for the tunnel.
	RateLimits *common.RateLimits `json:",omitempty"`

	// PacketTunnelTunDeviceFileDescriptor specifies a tun device file
	// descriptor to use for running a packet tunnel. When this value is > 0,
	// a packet tunnel is established through the server and packets are
	// relayed via the tun device file descriptor. The file descriptor is
	// duped in NewController. When PacketTunnelTunDeviceFileDescriptor is
	// set, TunnelPoolSize must be 1.
	PacketTunnelTunFileDescriptor int `json:",omitempty"`

	// PacketTunnelTransparentDNSIPv4Address is the IPv4 address of the DNS
	// server configured by a VPN using a packet tunnel. All DNS packets
	// destined to this DNS server are transparently redirected to the
	// Psiphon server DNS.
	PacketTunnelTransparentDNSIPv4Address string `json:",omitempty"`

	// PacketTunnelTransparentDNSIPv6Address is the IPv6 address of the DNS
	// server configured by a VPN using a packet tunnel. All DNS packets
	// destined to this DNS server are transparently redirected to the
	// Psiphon server DNS.
	PacketTunnelTransparentDNSIPv6Address string `json:",omitempty"`

	// SessionID specifies a client session ID to use in the Psiphon API. The
	// session ID should be a randomly generated value that is used only for a
	// single session, which is defined as the period between a user starting
	// a Psiphon client and stopping the client.
	//
	// A session ID must be 32 hex digits (lower case). When blank, a random
	// session ID is automatically generated. Supply a session ID when a
	// single client session will cross multiple Controller instances.
	SessionID string `json:",omitempty"`

	// Authorizations is a list of encoded, signed access control
	// authorizations that the client has obtained and will present to the
	// server.
	Authorizations []string `json:",omitempty"`

	// ServerEntrySignaturePublicKey is a base64-encoded, ed25519 public
	// key value used to verify individual server entry signatures. This value
	// is supplied by and depends on the Psiphon Network, and is typically
	// embedded in the client binary.
	ServerEntrySignaturePublicKey string `json:",omitempty"`

	// ExchangeObfuscationKey is a base64-encoded, NaCl secretbox key used to
	// obfuscate server info exchanges between clients.
	// Required for the exchange functionality.
	ExchangeObfuscationKey string `json:",omitempty"`

	// MigrateHomepageNoticesFilename migrates a homepage file from the path
	// previously configured with setNoticeFiles to the new path for homepage
	// files under the data root directory. The file specified by this config
	// value will be moved to config.GetHomePageFilename().
	//
	// Note: see comment for config.Commit() for a description of how file
	// migrations are performed.
	//
	// If not set, no migration operation will be performed.
	MigrateHomepageNoticesFilename string `json:",omitempty"`

	// MigrateRotatingNoticesFilename migrates notice files from the path
	// previously configured with setNoticeFiles to the new path for notice
	// files under the data root directory.
	//
	// MigrateRotatingNoticesFilename will be moved to
	// config.GetNoticesFilename().
	//
	// MigrateRotatingNoticesFilename.1 will be moved to
	// config.GetOldNoticesFilename().
	//
	// Note: see comment for config.Commit() for a description of how file
	// migrations are performed.
	//
	// If not set, no migration operation will be performed.
	MigrateRotatingNoticesFilename string `json:",omitempty"`

	// MigrateDataStoreDirectory indicates the location of the datastore
	// directory, as previously configured with the deprecated
	// DataStoreDirectory config field. Datastore files found in the specified
	// directory will be moved under the data root directory.
	//
	// Note: see comment for config.Commit() for a description of how file
	// migrations are performed.
	MigrateDataStoreDirectory string `json:",omitempty"`

	// MigrateRemoteServerListDownloadFilename indicates the location of
	// remote server list download files. The remote server list files found at
	// the specified path will be moved under the data root directory.
	//
	// Note: see comment for config.Commit() for a description of how file
	// migrations are performed.
	MigrateRemoteServerListDownloadFilename string `json:",omitempty"`

	// MigrateObfuscatedServerListDownloadDirectory indicates the location of
	// the obfuscated server list downloads directory, as previously configured
	// with ObfuscatedServerListDownloadDirectory. Obfuscated server list
	// download files found in the specified directory will be moved under the
	// data root directory.
	//
	// Warning: if the directory is empty after obfuscated server
	// list files are moved, then it will be deleted.
	//
	// Note: see comment for config.Commit() for a description of how file
	// migrations are performed.
	MigrateObfuscatedServerListDownloadDirectory string `json:",omitempty"`

	// MigrateUpgradeDownloadFilename indicates the location of downloaded
	// application upgrade files. Downloaded upgrade files found at the
	// specified path will be moved under the data root directory.
	//
	// Note: see comment for config.Commit() for a description of how file
	// migrations are performed.
	MigrateUpgradeDownloadFilename string `json:",omitempty"`

	// DisableTunnels disables establishing a client tunnel. Set
	// DisableTunnels when running a stand-alone in-proxy proxy.
	DisableTunnels bool `json:",omitempty"`

	// InproxyEnableProxy enables running an in-proxy proxy.
	InproxyEnableProxy bool `json:",omitempty"`

	// InproxyProxySessionPrivateKey specifies a long-term in-proxy proxy
	// private key and corresponding, derived proxy ID to use. If blank, an
	// ephemeral key will be generated.
	InproxyProxySessionPrivateKey string `json:",omitempty"`

	// InproxyMaxClients specifies the maximum number of in-proxy clients to
	// be proxied concurrently. Must be > 0 when InproxyEnableProxy is set.
	InproxyMaxClients int `json:",omitempty"`

	// InproxyLimitUpstreamBytesPerSecond specifies the upstream byte transfer
	// rate limit for each proxied client. When 0, there is no limit.
	InproxyLimitUpstreamBytesPerSecond int `json:",omitempty"`

	// InproxyLimitDownstreamBytesPerSecond specifies the downstream byte
	// transfer rate limit for each proxied client. When 0, there is no limit.
	InproxyLimitDownstreamBytesPerSecond int `json:",omitempty"`

	// InproxyReducedStartTime specifies the local time of day(HH:MM, 24-hour,
	// UTC) at which reduced in-proxy settings begin.
	InproxyReducedStartTime string `json:",omitempty"`

	// InproxyReducedEndTime specifies the local time of day (HH:MM, 24-hour,
	// UTC) at which reduced in-proxy settings end.
	InproxyReducedEndTime string `json:",omitempty"`

	// InproxyReducedMaxClients specifies the maximum number of in-proxy
	// clients to be proxied concurrently during the reduced time range.
	// When set, must be > 0 and <= InproxyMaxClients.
	//
	// Clients connected when the reduced settings begin will not be
	// disconnected, so InproxyReducedMaxClients is a soft limit.
	InproxyReducedMaxClients int `json:",omitempty"`

	// InproxyReducedLimitUpstreamBytesPerSecond specifies the upstream byte
	// transfer rate limit for each proxied client during the reduced time
	// range. When 0, InproxyLimitUpstreamBytesPerSecond is the limit.
	//
	// Rates for clients already connected when the reduced settings begin or
	// end will not change.
	InproxyReducedLimitUpstreamBytesPerSecond int `json:",omitempty"`

	// InproxyReducedLimitDownstreamBytesPerSecond specifies the downstream byte
	// transfer rate limit for each proxied client during the reduced time
	// range. When 0, InproxyLimitDownstreamBytesPerSecond is the limit.
	//
	// Rates for clients already connected when the reduced settings begin or
	// end will not change.
	InproxyReducedLimitDownstreamBytesPerSecond int `json:",omitempty"`

	// InproxyProxyPersonalCompartmentID specifies the personal compartment
	// ID used by an in-proxy proxy. Personal compartment IDs are
	// distributed from proxy operators to client users out-of-band and
	// provide a mechanism to allow only certain clients to use a proxy.
	InproxyProxyPersonalCompartmentID string `json:",omitempty"`

	// InproxyClientPersonalCompartmentID specifies the personal compartment
	// ID used by an in-proxy client. Personal compartment IDs are
	// distributed from proxy operators to client users out-of-band and
	// provide a mechanism to ensure a client uses only a certain proxy for
	// all tunnels connections.
	//
	// When an InproxyClientPersonalCompartmentID is set, the client will use
	// only in-proxy protocols, ensuring that all connections go through the
	// proxy or proxies with the same personal compartment ID.
	InproxyClientPersonalCompartmentID string `json:",omitempty"`

	// InproxyPersonalPairingConnectionWorkerPoolSize specifies the value for
	// ConnectionWorkerPoolSize in personal pairing mode. If omitted or when
	// 0, a default is used; this is recommended.
	InproxyPersonalPairingConnectionWorkerPoolSize int `json:",omitempty"`

	// EmitInproxyProxyActivity indicates whether to emit frequent notices
	// showing proxy connection information and bytes transferred.
	EmitInproxyProxyActivity bool `json:",omitempty"`

	// ShutdownGoroutineProfileDeadlineSeconds is the number of seconds to
	// await shutdown in Controller.Run before dumping a goroutine profile to
	// diagnostics. Specify 0 to disable. When not specified, the default is
	// 60 seconds.
	ShutdownGoroutineProfileDeadlineSeconds *int `json:",omitempty"`

	// DisableDSLFetcher disables DSL fetches. If set, this overrides the
	// EnableDSLFetcher tactics parameter. This may be used for special case
	// temporary tunnels.
	DisableDSLFetcher bool `json:",omitempty"`

	//
	// The following parameters are deprecated.
	//

	// DataStoreDirectory is the directory in which to store the persistent
	// database, which contains information such as server entries. By
	// default, current working directory.
	//
	// Deprecated:
	// Use MigrateDataStoreDirectory. When MigrateDataStoreDirectory
	// is set, this parameter is ignored.
	//
	// DataStoreDirectory has been subsumed by the new data root directory,
	// which is configured with DataRootDirectory. If set, datastore files
	// found in the specified directory will be moved under the data root
	// directory.
	DataStoreDirectory string `json:",omitempty"`

	// RemoteServerListDownloadFilename specifies a target filename for
	// storing the remote server list download. Data is stored in co-located
	// files (RemoteServerListDownloadFilename.part*) to allow for resumable
	// downloading.
	//
	// Deprecated:
	// Use MigrateRemoteServerListDownloadFilename. When
	// MigrateRemoteServerListDownloadFilename is set, this parameter is
	// ignored.
	//
	// If set, remote server list download files found at the specified path
	// will be moved under the data root directory.
	RemoteServerListDownloadFilename string `json:",omitempty"`

	// ObfuscatedServerListDownloadDirectory specifies a target directory for
	// storing the obfuscated remote server list downloads. Data is stored in
	// co-located files (<OSL filename>.part*) to allow for resumable
	// downloading.
	//
	// Deprecated:
	// Use MigrateObfuscatedServerListDownloadDirectory. When
	// MigrateObfuscatedServerListDownloadDirectory is set, this parameter is
	// ignored.
	//
	// If set, obfuscated server list download files found at the specified path
	// will be moved under the data root directory.
	ObfuscatedServerListDownloadDirectory string `json:",omitempty"`

	// UpgradeDownloadFilename is the local target filename for an upgrade
	// download. This parameter is required when UpgradeDownloadURLs (or
	// UpgradeDownloadUrl) is specified. Data is stored in co-located files
	// (UpgradeDownloadFilename.part*) to allow for resumable downloading.
	//
	// Deprecated:
	// Use MigrateUpgradeDownloadFilename. When MigrateUpgradeDownloadFilename
	// is set, this parameter is ignored.
	//
	// If set, upgrade download files found at the specified path will be moved
	// under the data root directory.
	UpgradeDownloadFilename string `json:",omitempty"`

	// TunnelProtocol indicates which protocol to use. For the default, "",
	// all protocols are used.
	//
	// Deprecated: Use LimitTunnelProtocols. When LimitTunnelProtocols is not
	// nil, this parameter is ignored.
	TunnelProtocol string `json:",omitempty"`

	// Deprecated: Use CustomHeaders. When CustomHeaders is not nil, this
	// parameter is ignored.
	UpstreamProxyCustomHeaders http.Header `json:",omitempty"`

	// RemoteServerListUrl is a URL which specifies a location to fetch out-
	// of-band server entries. This facility is used when a tunnel cannot be
	// established to known servers. This value is supplied by and depends on
	// the Psiphon Network, and is typically embedded in the client binary.
	//
	// Deprecated: Use RemoteServerListURLs. When RemoteServerListURLs is not
	// nil, this parameter is ignored.
	RemoteServerListUrl string `json:",omitempty"`

	// ObfuscatedServerListRootURL is a URL which specifies the root location
	// from which to fetch obfuscated server list files. This value is
	// supplied by and depends on the Psiphon Network, and is typically
	// embedded in the client binary.
	//
	// Deprecated: Use ObfuscatedServerListRootURLs. When
	// ObfuscatedServerListRootURLs is not nil, this parameter is ignored.
	ObfuscatedServerListRootURL string `json:",omitempty"`

	// UpgradeDownloadUrl specifies a URL from which to download a host client
	// upgrade file, when one is available. The core tunnel controller
	// provides a resumable download facility which downloads this resource
	// and emits a notice when complete. This value is supplied by and depends
	// on the Psiphon Network, and is typically embedded in the client binary.
	//
	// Deprecated: Use UpgradeDownloadURLs. When UpgradeDownloadURLs is not
	// nil, this parameter is ignored.
	UpgradeDownloadUrl string `json:",omitempty"`

	//
	// The following parameters are for testing purposes.
	//

	// TransformHostNameProbability is for testing purposes.
	TransformHostNameProbability *float64 `json:",omitempty"`

	// FragmentorProbability and associated Fragmentor fields are for testing
	// purposes.
	FragmentorProbability          *float64 `json:",omitempty"`
	FragmentorLimitProtocols       []string `json:",omitempty"`
	FragmentorMinTotalBytes        *int     `json:",omitempty"`
	FragmentorMaxTotalBytes        *int     `json:",omitempty"`
	FragmentorMinWriteBytes        *int     `json:",omitempty"`
	FragmentorMaxWriteBytes        *int     `json:",omitempty"`
	FragmentorMinDelayMicroseconds *int     `json:",omitempty"`
	FragmentorMaxDelayMicroseconds *int     `json:",omitempty"`

	// MeekTrafficShapingProbability and associated fields are for testing
	// purposes.
	MeekTrafficShapingProbability       *float64 `json:",omitempty"`
	MeekTrafficShapingLimitProtocols    []string `json:",omitempty"`
	MeekMinTLSPadding                   *int     `json:",omitempty"`
	MeekMaxTLSPadding                   *int     `json:",omitempty"`
	MeekMinLimitRequestPayloadLength    *int     `json:",omitempty"`
	MeekMaxLimitRequestPayloadLength    *int     `json:",omitempty"`
	MeekRedialTLSProbability            *float64 `json:",omitempty"`
	MeekAlternateCookieNameProbability  *float64 `json:",omitempty"`
	MeekAlternateContentTypeProbability *float64 `json:",omitempty"`

	// ObfuscatedSSHAlgorithms and associated ObfuscatedSSH fields are for
	// testing purposes. If specified, ObfuscatedSSHAlgorithms must have 4 SSH
	// KEX elements in order: the kex algorithm, cipher, MAC, and server host
	// key algorithm.
	ObfuscatedSSHAlgorithms []string `json:",omitempty"`
	ObfuscatedSSHMinPadding *int     `json:",omitempty"`
	ObfuscatedSSHMaxPadding *int     `json:",omitempty"`

	// LivenessTestMinUpstreamBytes and other LivenessTest fields are for
	// testing purposes.
	InitialLivenessTest            parameters.LivenessTestSpecs `json:",omitempty"`
	LivenessTest                   parameters.LivenessTestSpecs `json:",omitempty"`
	LivenessTestMinUpstreamBytes   *int                         `json:",omitempty"`
	LivenessTestMaxUpstreamBytes   *int                         `json:",omitempty"`
	LivenessTestMinDownstreamBytes *int                         `json:",omitempty"`
	LivenessTestMaxDownstreamBytes *int                         `json:",omitempty"`

	// ReplayCandidateCount and other Replay fields are for testing purposes.
	ReplayCandidateCount                      *int     `json:",omitempty"`
	ReplayDialParametersTTLSeconds            *int     `json:",omitempty"`
	ReplayTargetUpstreamBytes                 *int     `json:",omitempty"`
	ReplayTargetDownstreamBytes               *int     `json:",omitempty"`
	ReplayTargetTunnelDurationSeconds         *int     `json:",omitempty"`
	ReplayLaterRoundMoveToFrontProbability    *float64 `json:",omitempty"`
	ReplayRetainFailedProbability             *float64 `json:",omitempty"`
	ReplayIgnoreChangedConfigStateProbability *float64 `json:",omitempty"`

	// NetworkLatencyMultiplierMin and other NetworkLatencyMultiplier fields are
	// for testing purposes.
	NetworkLatencyMultiplierMin    float64 `json:",omitempty"`
	NetworkLatencyMultiplierMax    float64 `json:",omitempty"`
	NetworkLatencyMultiplierLambda float64 `json:",omitempty"`

	// UseOnlyCustomTLSProfiles and other TLS configuration fields are for
	// testing purposes.
	UseOnlyCustomTLSProfiles              *bool                       `json:",omitempty"`
	CustomTLSProfiles                     protocol.CustomTLSProfiles  `json:",omitempty"`
	SelectRandomizedTLSProfileProbability *float64                    `json:",omitempty"`
	NoDefaultTLSSessionIDProbability      *float64                    `json:",omitempty"`
	DisableFrontingProviderTLSProfiles    protocol.LabeledTLSProfiles `json:",omitempty"`

	// ClientBurstUpstreamTargetBytes and other burst metric fields are for
	// testing purposes.
	ClientBurstUpstreamTargetBytes            *int `json:",omitempty"`
	ClientBurstUpstreamDeadlineMilliseconds   *int `json:",omitempty"`
	ClientBurstDownstreamTargetBytes          *int `json:",omitempty"`
	ClientBurstDownstreamDeadlineMilliseconds *int `json:",omitempty"`

	// CustomHostNameRegexes and other custom host name fields are for testing
	// purposes.
	CustomHostNameRegexes        []string `json:",omitempty"`
	CustomHostNameProbability    *float64 `json:",omitempty"`
	CustomHostNameLimitProtocols []string `json:",omitempty"`

	// ConjureCachedRegistrationTTLSeconds and other Conjure fields are for
	// testing purposes.
	ConjureCachedRegistrationTTLSeconds       *int                       `json:",omitempty"`
	ConjureAPIRegistrarBidirectionalURL       string                     `json:",omitempty"`
	ConjureAPIRegistrarFrontingSpecs          parameters.FrontingSpecs   `json:",omitempty"`
	ConjureAPIRegistrarMinDelayMilliseconds   *int                       `json:",omitempty"`
	ConjureAPIRegistrarMaxDelayMilliseconds   *int                       `json:",omitempty"`
	ConjureDecoyRegistrarProbability          *float64                   `json:",omitempty"`
	ConjureDecoyRegistrarWidth                *int                       `json:",omitempty"`
	ConjureDecoyRegistrarMinDelayMilliseconds *int                       `json:",omitempty"`
	ConjureDecoyRegistrarMaxDelayMilliseconds *int                       `json:",omitempty"`
	ConjureEnableIPv6Dials                    *bool                      `json:",omitempty"`
	ConjureEnablePortRandomization            *bool                      `json:",omitempty"`
	ConjureEnableRegistrationOverrides        *bool                      `json:",omitempty"`
	ConjureLimitTransports                    protocol.ConjureTransports `json:",omitempty"`
	ConjureSTUNServerAddresses                []string                   `json:",omitempty"`
	ConjureDTLSEmptyInitialPacketProbability  *float64                   `json:",omitempty"`

	// HoldOffTunnelProtocolMinDurationMilliseconds and other
	// HoldOffTunnelProtocol fields are for testing purposes.
	HoldOffTunnelProtocolMinDurationMilliseconds *int     `json:",omitempty"`
	HoldOffTunnelProtocolMaxDurationMilliseconds *int     `json:",omitempty"`
	HoldOffTunnelProtocolNames                   []string `json:",omitempty"`
	HoldOffTunnelProtocolProbability             *float64 `json:",omitempty"`

	// HoldOffFrontingTunnelMinDurationMilliseconds and other
	// HoldOffFrontingTunnel fields are for testing purposes.
	HoldOffFrontingTunnelMinDurationMilliseconds *int     `json:",omitempty"`
	HoldOffFrontingTunnelMaxDurationMilliseconds *int     `json:",omitempty"`
	HoldOffFrontingTunnelProviderIDs             []string `json:",omitempty"`
	HoldOffFrontingTunnelProbability             *float64 `json:",omitempty"`

	// RestrictFrontingProviderIDs and other RestrictFrontingProviderIDs fields
	// are for testing purposes.
	RestrictFrontingProviderIDs                  []string `json:",omitempty"`
	RestrictFrontingProviderIDsClientProbability *float64 `json:",omitempty"`

	// HoldOffDirectTunnelMinDurationMilliseconds and other HoldOffDirect
	// fields are for testing purposes.
	HoldOffDirectTunnelMinDurationMilliseconds *int                `json:",omitempty"`
	HoldOffDirectTunnelMaxDurationMilliseconds *int                `json:",omitempty"`
	HoldOffDirectTunnelProviderRegions         map[string][]string `json:",omitempty"`
	HoldOffDirectTunnelProbability             *float64            `json:",omitempty"`

	// RestrictDirectProviderRegions and other RestrictDirect fields are for
	// testing purposes.
	RestrictDirectProviderRegions              map[string][]string `json:",omitempty"`
	RestrictDirectProviderIDsClientProbability *float64            `json:",omitempty"`

	// HoldOffInproxyTunnelMinDurationMilliseconds and other HoldOffInproxy
	// fields are for testing purposes.
	HoldOffInproxyTunnelMinDurationMilliseconds *int                `json:",omitempty"`
	HoldOffInproxyTunnelMaxDurationMilliseconds *int                `json:",omitempty"`
	HoldOffInproxyTunnelProviderRegions         map[string][]string `json:",omitempty"`
	HoldOffInproxyTunnelProbability             *float64            `json:",omitempty"`

	// RestrictInproxyProviderRegions and other RestrictInproxy fields are for
	// testing purposes.
	RestrictInproxyProviderRegions              map[string][]string `json:",omitempty"`
	RestrictInproxyProviderIDsClientProbability *float64            `json:",omitempty"`

	// UpstreamProxyAllowAllServerEntrySources is for testing purposes.
	UpstreamProxyAllowAllServerEntrySources *bool `json:",omitempty"`

	// LimitTunnelDialPortNumbers is for testing purposes.
	LimitTunnelDialPortNumbers parameters.TunnelProtocolPortLists `json:",omitempty"`

	// QUICDialEarlyProbability is for testing purposes.
	QUICDialEarlyProbability *float64 `json:",omitempty"`

	// QUICObfuscatedPSKProbability is for testing purposes.
	QUICObfuscatedPSKProbability *float64 `json:",omitempty"`

	// QUICDisablePathMTUDiscoveryProbability is for testing purposes.
	QUICDisablePathMTUDiscoveryProbability *float64 `json:",omitempty"`

	// DNSResolverAttemptsPerServer and other DNSResolver fields are for
	// testing purposes.
	DNSResolverAttemptsPerServer                     *int                       `json:",omitempty"`
	DNSResolverAttemptsPerPreferredServer            *int                       `json:",omitempty"`
	DNSResolverRequestTimeoutMilliseconds            *int                       `json:",omitempty"`
	DNSResolverAwaitTimeoutMilliseconds              *int                       `json:",omitempty"`
	DNSResolverPreresolvedIPAddressCIDRs             parameters.LabeledCIDRs    `json:",omitempty"`
	DNSResolverPreresolvedIPAddressProbability       *float64                   `json:",omitempty"`
	DNSResolverAlternateServers                      []string                   `json:",omitempty"`
	DNSResolverPreferredAlternateServers             []string                   `json:",omitempty"`
	DNSResolverPreferAlternateServerProbability      *float64                   `json:",omitempty"`
	DNSResolverProtocolTransformSpecs                transforms.Specs           `json:",omitempty"`
	DNSResolverProtocolTransformScopedSpecNames      transforms.ScopedSpecNames `json:",omitempty"`
	DNSResolverProtocolTransformProbability          *float64                   `json:",omitempty"`
	DNSResolverQNameRandomizeCasingProbability       *float64                   `json:",omitempty"`
	DNSResolverQNameMustMatchProbability             *float64                   `json:",omitempty"`
	DNSResolverIncludeEDNS0Probability               *float64                   `json:",omitempty"`
	DNSResolverCacheExtensionInitialTTLMilliseconds  *int                       `json:",omitempty"`
	DNSResolverCacheExtensionVerifiedTTLMilliseconds *int                       `json:",omitempty"`

	DirectHTTPProtocolTransformSpecs            transforms.Specs           `json:",omitempty"`
	DirectHTTPProtocolTransformScopedSpecNames  transforms.ScopedSpecNames `json:",omitempty"`
	DirectHTTPProtocolTransformProbability      *float64                   `json:",omitempty"`
	FrontedHTTPProtocolTransformSpecs           transforms.Specs           `json:",omitempty"`
	FrontedHTTPProtocolTransformScopedSpecNames transforms.ScopedSpecNames `json:",omitempty"`
	FrontedHTTPProtocolTransformProbability     *float64                   `json:",omitempty"`

	OSSHObfuscatorSeedTransformSpecs           transforms.Specs           `json:",omitempty"`
	OSSHObfuscatorSeedTransformScopedSpecNames transforms.ScopedSpecNames `json:",omitempty"`
	OSSHObfuscatorSeedTransformProbability     *float64                   `json:",omitempty"`

	ObfuscatedQUICNonceTransformSpecs           transforms.Specs           `json:",omitempty"`
	ObfuscatedQUICNonceTransformScopedSpecNames transforms.ScopedSpecNames `json:",omitempty"`
	ObfuscatedQUICNonceTransformProbability     *float64                   `json:",omitempty"`

	// OSSHPrefix parameters are for testing purposes only.
	OSSHPrefixSpecs                     transforms.Specs           `json:",omitempty"`
	OSSHPrefixScopedSpecNames           transforms.ScopedSpecNames `json:",omitempty"`
	OSSHPrefixProbability               *float64                   `json:",omitempty"`
	OSSHPrefixSplitMinDelayMilliseconds *int                       `json:",omitempty"`
	OSSHPrefixSplitMaxDelayMilliseconds *int                       `json:",omitempty"`
	OSSHPrefixEnableFragmentor          *bool                      `json:",omitempty"`

	// ShadowsocksPrefix parameters are for testing purposes only.
	ShadowsocksPrefixSpecs           transforms.Specs           `json:",omitempty"`
	ShadowsocksPrefixScopedSpecNames transforms.ScopedSpecNames `json:",omitempty"`
	ShadowsocksPrefixProbability     *float64                   `json:",omitempty"`

	// TLSTunnelTrafficShapingProbability and associated fields are for testing.
	TLSTunnelObfuscatedPSKProbability  *float64 `json:",omitempty"`
	TLSTunnelTrafficShapingProbability *float64 `json:",omitempty"`
	TLSTunnelMinTLSPadding             *int     `json:",omitempty"`
	TLSTunnelMaxTLSPadding             *int     `json:",omitempty"`

	// TLSFragmentClientHello fields are for testing purposes only.
	TLSFragmentClientHelloProbability    *float64 `json:",omitempty"`
	TLSFragmentClientHelloLimitProtocols []string `json:",omitempty"`

	// AdditionalParameters is used for testing.
	AdditionalParameters string `json:",omitempty"`

	// SteeringIP fields are for testing purposes only.
	SteeringIPCacheTTLSeconds *int     `json:",omitempty"`
	SteeringIPCacheMaxEntries *int     `json:",omitempty"`
	SteeringIPProbability     *float64 `json:",omitempty"`

	// FrontedHTTPClientReplayDialParametersTTL and other FrontedHTTPClient
	// fields are for testing purposes only.
	FrontedHTTPClientReplayDialParametersTTLSeconds  *int     `json:",omitempty"`
	FrontedHTTPClientReplayUpdateFrequencySeconds    *int     `json:",omitempty"`
	FrontedHTTPClientReplayDialParametersProbability *float64 `json:",omitempty"`
	FrontedHTTPClientReplayRetainFailedProbability   *float64 `json:",omitempty"`

	// The following in-proxy fields are for testing purposes only.
	InproxyAllowProxy                                       *bool                                            `json:",omitempty"`
	InproxyAllowClient                                      *bool                                            `json:",omitempty"`
	InproxyTunnelProtocolSelectionProbability               *float64                                         `json:",omitempty"`
	InproxyBrokerSpecs                                      parameters.InproxyBrokerSpecsValue               `json:",omitempty"`
	InproxyPersonalPairingBrokerSpecs                       parameters.InproxyBrokerSpecsValue               `json:",omitempty"`
	InproxyProxyBrokerSpecs                                 parameters.InproxyBrokerSpecsValue               `json:",omitempty"`
	InproxyProxyPersonalPairingBrokerSpecs                  parameters.InproxyBrokerSpecsValue               `json:",omitempty"`
	InproxyClientBrokerSpecs                                parameters.InproxyBrokerSpecsValue               `json:",omitempty"`
	InproxyClientPersonalPairingBrokerSpecs                 parameters.InproxyBrokerSpecsValue               `json:",omitempty"`
	InproxyReplayBrokerDialParametersTTLSeconds             *int                                             `json:",omitempty"`
	InproxyReplayBrokerUpdateFrequencySeconds               *int                                             `json:",omitempty"`
	InproxyReplayBrokerDialParametersProbability            *float64                                         `json:",omitempty"`
	InproxyReplayBrokerRetainFailedProbability              *float64                                         `json:",omitempty"`
	InproxyCommonCompartmentIDs                             parameters.InproxyCompartmentIDsValue            `json:",omitempty"`
	InproxyMaxCompartmentIDListLength                       *int                                             `json:",omitempty"`
	InproxyProxyAnnounceRequestTimeoutMilliseconds          *int                                             `json:",omitempty"`
	InproxyProxyAnnounceDelayMilliseconds                   *int                                             `json:",omitempty"`
	InproxyProxyAnnounceMaxBackoffDelayMilliseconds         *int                                             `json:",omitempty"`
	InproxyProxyAnnounceDelayJitter                         *float64                                         `json:",omitempty"`
	InproxyProxyAnswerRequestTimeoutMilliseconds            *int                                             `json:",omitempty"`
	InproxyClientOfferRequestTimeoutMilliseconds            *int                                             `json:",omitempty"`
	InproxyClientOfferRequestPersonalTimeoutMilliseconds    *int                                             `json:",omitempty"`
	InproxyClientOfferRetryDelayMilliseconds                *int                                             `json:",omitempty"`
	InproxyClientOfferRetryJitter                           *float64                                         `json:",omitempty"`
	InproxyClientRelayedPacketRequestTimeoutMilliseconds    *int                                             `json:",omitempty"`
	InproxyDTLSRandomizationProbability                     *float64                                         `json:",omitempty"`
	InproxyWebRTCMediaStreamsProbability                    *float64                                         `json:",omitempty"`
	InproxyWebRTCDataChannelTrafficShapingProbability       *float64                                         `json:",omitempty"`
	InproxyWebRTCDataChannelTrafficShapingParameters        *parameters.InproxyTrafficShapingParametersValue `json:",omitempty"`
	InproxyWebRTCMediaStreamsTrafficShapingProbability      *float64                                         `json:",omitempty"`
	InproxyWebRTCMediaStreamsTrafficShapingParameters       *parameters.InproxyTrafficShapingParametersValue `json:",omitempty"`
	InproxySTUNServerAddresses                              []string                                         `json:",omitempty"`
	InproxySTUNServerAddressesRFC5780                       []string                                         `json:",omitempty"`
	InproxyProxySTUNServerAddresses                         []string                                         `json:",omitempty"`
	InproxyProxySTUNServerAddressesRFC5780                  []string                                         `json:",omitempty"`
	InproxyClientSTUNServerAddresses                        []string                                         `json:",omitempty"`
	InproxyClientSTUNServerAddressesRFC5780                 []string                                         `json:",omitempty"`
	InproxyClientDiscoverNATProbability                     *float64                                         `json:",omitempty"`
	InproxyDisableSTUN                                      *bool                                            `json:",omitempty"`
	InproxyDisablePortMapping                               *bool                                            `json:",omitempty"`
	InproxyDisableInboundForMobileNetworks                  *bool                                            `json:",omitempty"`
	InproxyDisableIPv6ICECandidates                         *bool                                            `json:",omitempty"`
	InproxyProxyDisableSTUN                                 *bool                                            `json:",omitempty"`
	InproxyProxyDisablePortMapping                          *bool                                            `json:",omitempty"`
	InproxyProxyDisableInboundForMobileNetworks             *bool                                            `json:",omitempty"`
	InproxyProxyDisableIPv6ICECandidates                    *bool                                            `json:",omitempty"`
	InproxyClientDisableSTUN                                *bool                                            `json:",omitempty"`
	InproxyClientDisablePortMapping                         *bool                                            `json:",omitempty"`
	InproxyClientDisableInboundForMobileNetworks            *bool                                            `json:",omitempty"`
	InproxyClientDisableIPv6ICECandidates                   *bool                                            `json:",omitempty"`
	InproxyProxyDiscoverNATTimeoutMilliseconds              *int                                             `json:",omitempty"`
	InproxyClientDiscoverNATTimeoutMilliseconds             *int                                             `json:",omitempty"`
	InproxyWebRTCAnswerTimeoutMilliseconds                  *int                                             `json:",omitempty"`
	InproxyProxyWebRTCAwaitReadyToProxyTimeoutMilliseconds  *int                                             `json:",omitempty"`
	InproxyClientWebRTCAwaitReadyToProxyTimeoutMilliseconds *int                                             `json:",omitempty"`
	InproxyProxyDestinationDialTimeoutMilliseconds          *int                                             `json:",omitempty"`
	InproxyPsiphonAPIRequestTimeoutMilliseconds             *int                                             `json:",omitempty"`
	InproxyProxyTotalActivityNoticePeriodMilliseconds       *int                                             `json:",omitempty"`
	InproxyClientDialRateLimitQuantity                      *int                                             `json:",omitempty"`
	InproxyClientDialRateLimitIntervalMilliseconds          *int                                             `json:",omitempty"`
	InproxyClientNoMatchFailoverProbability                 *float64                                         `json:",omitempty"`
	InproxyClientNoMatchFailoverPersonalProbability         *float64                                         `json:",omitempty"`
	InproxyFrontingProviderClientMaxRequestTimeouts         map[string]string                                `json:",omitempty"`
	InproxyProxyOnBrokerClientFailedRetryPeriodMilliseconds *int                                             `json:",omitempty"`
	InproxyProxyIncompatibleNetworkTypes                    []string                                         `json:",omitempty"`
	InproxyClientIncompatibleNetworkTypes                   []string                                         `json:",omitempty"`
	InproxyReplayRetainFailedProbability                    *float64                                         `json:",omitempty"`
	InproxyProxyDisableWaitToShareSession                   *bool                                            `json:",omitempty"`
	InproxyClientDisableWaitToShareSession                  *bool                                            `json:",omitempty"`
	InproxyTunnelProtocolPreferProbability                  *float64                                         `json:",omitempty"`
	InproxyTunnelProtocolForceSelectionCount                *int                                             `json:",omitempty"`

	InproxySkipAwaitFullyConnected  bool `json:",omitempty"`
	InproxyEnableWebRTCDebugLogging bool `json:",omitempty"`

	NetworkIDCacheTTLMilliseconds *int `json:",omitempty"`

	CompressTactics *bool `json:",omitempty"`

	EnableDSLFetcher                                *bool    `json:",omitempty"`
	DSLPrioritizeDialNewServerEntryProbability      *float64 `json:",omitempty"`
	DSLPrioritizeDialExistingServerEntryProbability *float64 `json:",omitempty"`
	DSLPrioritizeDialRetainFailedProbability        *float64 `json:",omitempty"`
	DSLPrioritizeDialPlaceholderTTLSeconds          *int     `json:",omitempty"`

	ServerEntryIteratorMaxMoveToFront   *int     `json:",omitempty"`
	ServerEntryIteratorResetProbability *float64 `json:",omitempty"`

	// params is the active parameters.Parameters with defaults, config values,
	// and, optionally, tactics applied.
	//
	// New tactics must be applied by calling Config.SetParameters; calling
	// params.Set directly will fail to add config values.
	paramsMutex sync.Mutex
	params      *parameters.Parameters

	dialParametersHash []byte

	dynamicConfigMutex sync.Mutex
	sponsorID          string
	authorizations     []string

	deviceBinder    DeviceBinder
	networkIDGetter *cachingNetworkIDGetter

	clientFeatures []string

	resolverMutex sync.Mutex
	resolver      *resolver.Resolver

	committed bool

	loadTimestamp string

	tacticsAppliedReceiversMutex sync.Mutex
	tacticsAppliedReceivers      []TacticsAppliedReceiver

	signalComponentFailure atomic.Value

	inproxyMustUpgradePosted int32

	serverEntryIterationMetricsUpdater atomic.Value
}

// TacticsAppliedReceiver specifies the interface for a component that is
// signaled when tactics are applied. TacticsApplied is invoked when any
// tactics are applied after initial start up, and then whenever new tactics
// are received and applied while running.
type TacticsAppliedReceiver interface {
	TacticsApplied() error
}

// Config field which specifies if notice files should be used and at which
// frequency and size they should be rotated.
//
// If either RotatingFileSize or RotatingSyncFrequency are <= 0, default values
// are used.
//
// See comment for setNoticeFiles in notice.go for further details.
type UseNoticeFiles struct {
	RotatingFileSize      int
	RotatingSyncFrequency int
}

// LoadConfig parses a JSON format Psiphon config JSON string and returns a
// Config struct populated with config values.
//
// The Config struct may then be programmatically populated with additional
// values, including callbacks such as DeviceBinder.
//
// Before using the Config, Commit must be called, which will perform further
// validation and initialize internal data structures.
func LoadConfig(configJson []byte) (*Config, error) {

	var config Config
	err := json.Unmarshal(configJson, &config)
	if err != nil {
		return nil, errors.Trace(err)
	}

	config.loadTimestamp = common.TruncateTimestampToHour(
		common.GetCurrentTimestamp())

	config.signalComponentFailure.Store(func() {})
	config.serverEntryIterationMetricsUpdater.Store(func(int) {})

	return &config, nil
}

// IsCommitted checks if Commit was called.
func (config *Config) IsCommitted() bool {
	return config.committed
}

// Commit validates Config fields finalizes initialization.
//
// Config fields should not be set after calling Config, as any changes may
// not be reflected in internal data structures.
//
// If migrateFromLegacyFields is set to true, then an attempt to migrate from
// legacy fields is made.
//
// Migration from legacy fields:
// Config fields of the naming Migrate* (e.g. MigrateDataStoreDirectory) specify
// a file migration operation which should be performed. These fields correspond
// to deprecated fields, which previously could be used to specify where Psiphon
// stored different sets of persistent files (e.g. MigrateDataStoreDirectory
// corresponds to the deprecated field DataStoreDirectory).
//
// Psiphon now stores all persistent data under the configurable
// DataRootDirectory (see Config.DataRootDirectory). The deprecated fields, and
// corresponding Migrate* fields, are now used to specify the file or directory
// path where, or under which, persistent files and directories created by
// previous versions of Psiphon exist, so they can be moved under the
// DataRootDirectory.
//
// For each migration operation:
//   - In the case of directories that could have defaulted to the current working
//     directory, persistent files and directories created by Psiphon are
//     precisely targeted to avoid moving files which were not created by Psiphon.
//   - If no file is found at the specified path, or an error is encountered while
//     migrating the file, then an error is logged and execution continues
//     normally.
//
// A sentinel file which signals that file migration has been completed, and
// should not be attempted again, is created under DataRootDirectory after one
// full pass through Commit(), regardless of whether file migration succeeds or
// fails. It is better to not endlessly retry file migrations on each Commit()
// because file system errors are expected to be rare and persistent files will
// be re-populated over time.
func (config *Config) Commit(migrateFromLegacyFields bool) error {

	// Apply any additional parameters first
	additionalParametersInfoMsgs, err := config.applyAdditionalParameters()
	if err != nil {
		return errors.TraceMsg(err, "failed to apply additional parameters")
	}

	// Do SetEmitDiagnosticNotices first, to ensure config file errors are
	// emitted.
	if config.EmitDiagnosticNotices {
		SetEmitDiagnosticNotices(
			true, config.EmitDiagnosticNetworkParameters)
	}

	// Migrate and set notice files before any operations that may emit an
	// error. This is to ensure config file errors are written to file when
	// notice files are configured with config.UseNoticeFiles.
	//
	// Note:
	// Errors encountered while configuring the data directory cannot be written
	// to notice files. This is because notices files are created within the
	// data directory.

	if config.DataRootDirectory == "" {
		wd, err := os.Getwd()
		if err != nil {
			return errors.Trace(common.RedactFilePathsError(err))
		}
		config.DataRootDirectory = wd
	}

	// Create root directory
	dataDirectoryPath := config.GetPsiphonDataDirectory()
	if !common.FileExists(dataDirectoryPath) {
		err := os.Mkdir(dataDirectoryPath, os.ModePerm)
		if err != nil {
			return errors.Tracef(
				"failed to create datastore directory with error: %s",
				common.RedactFilePathsError(err, dataDirectoryPath))
		}
	}

	// Check if the migration from legacy config fields has already been
	// completed. See the Migrate* config fields for more details.
	migrationCompleteFilePath := filepath.Join(config.GetPsiphonDataDirectory(), "migration_complete")
	needMigration := !common.FileExists(migrationCompleteFilePath)

	// Collect notices to emit them after notice files are set
	var noticeMigrationAlertMsgs []string
	var noticeMigrationInfoMsgs []string

	// Migrate notices first to ensure notice files are used for notices if
	// UseNoticeFiles is set.
	homepageFilePath := config.GetHomePageFilename()
	noticesFilePath := config.GetNoticesFilename()

	if migrateFromLegacyFields {
		if needMigration {

			// Move notice files that exist at legacy file paths under the data root
			// directory.

			noticeMigrationInfoMsgs = append(noticeMigrationInfoMsgs, "Config migration: need migration")
			noticeMigrations := migrationsFromLegacyNoticeFilePaths(config)

			successfulMigrations := 0

			for _, migration := range noticeMigrations {
				err := DoFileMigration(migration)
				if err != nil {
					alertMsg := fmt.Sprintf("Config migration: %s", errors.Trace(err))
					noticeMigrationAlertMsgs = append(noticeMigrationAlertMsgs, alertMsg)
				} else {
					successfulMigrations += 1
				}
			}
			infoMsg := fmt.Sprintf("Config migration: %d/%d notice files successfully migrated", successfulMigrations, len(noticeMigrations))
			noticeMigrationInfoMsgs = append(noticeMigrationInfoMsgs, infoMsg)
		} else {
			noticeMigrationInfoMsgs = append(noticeMigrationInfoMsgs, "Config migration: migration already completed")
		}
	}

	if config.UseNoticeFiles != nil {
		err := setNoticeFiles(
			homepageFilePath,
			noticesFilePath,
			config.UseNoticeFiles.RotatingFileSize,
			config.UseNoticeFiles.RotatingSyncFrequency)
		if err != nil {
			return errors.Trace(err)
		}
	}

	// Emit notices now that notice files are set if configured
	for _, msg := range additionalParametersInfoMsgs {
		NoticeInfo(msg)
	}
	for _, msg := range noticeMigrationAlertMsgs {
		NoticeWarning(msg)
	}
	for _, msg := range noticeMigrationInfoMsgs {
		NoticeInfo(msg)
	}

	// Promote legacy fields.

	if config.CustomHeaders == nil {
		config.CustomHeaders = config.UpstreamProxyCustomHeaders
		config.UpstreamProxyCustomHeaders = nil
	}

	if config.RemoteServerListUrl != "" && config.RemoteServerListURLs == nil {
		config.RemoteServerListURLs = promoteLegacyTransferURL(config.RemoteServerListUrl)
	}

	if config.ObfuscatedServerListRootURL != "" && config.ObfuscatedServerListRootURLs == nil {
		config.ObfuscatedServerListRootURLs = promoteLegacyTransferURL(config.ObfuscatedServerListRootURL)
	}

	if config.UpgradeDownloadUrl != "" && config.UpgradeDownloadURLs == nil {
		config.UpgradeDownloadURLs = promoteLegacyTransferURL(config.UpgradeDownloadUrl)
	}

	if config.TunnelProtocol != "" && len(config.LimitTunnelProtocols) == 0 {
		config.LimitTunnelProtocols = []string{config.TunnelProtocol}
	}

	if config.DataStoreDirectory != "" && config.MigrateDataStoreDirectory == "" {
		config.MigrateDataStoreDirectory = config.DataStoreDirectory
	}

	if config.RemoteServerListDownloadFilename != "" && config.MigrateRemoteServerListDownloadFilename == "" {
		config.MigrateRemoteServerListDownloadFilename = config.RemoteServerListDownloadFilename
	}

	if config.ObfuscatedServerListDownloadDirectory != "" && config.MigrateObfuscatedServerListDownloadDirectory == "" {
		config.MigrateObfuscatedServerListDownloadDirectory = config.ObfuscatedServerListDownloadDirectory
	}

	if config.UpgradeDownloadFilename != "" && config.MigrateUpgradeDownloadFilename == "" {
		config.MigrateUpgradeDownloadFilename = config.UpgradeDownloadFilename
	}

	// Supply default values.

	// Create datastore directory.
	dataStoreDirectoryPath := config.GetDataStoreDirectory()
	if !common.FileExists(dataStoreDirectoryPath) {
		err := os.Mkdir(dataStoreDirectoryPath, os.ModePerm)
		if err != nil {
			return errors.Tracef(
				"failed to create datastore directory with error: %s",
				common.RedactFilePathsError(err, dataStoreDirectoryPath))
		}
	}

	// Create OSL directory.
	oslDirectoryPath := config.GetObfuscatedServerListDownloadDirectory()
	if !common.FileExists(oslDirectoryPath) {
		err := os.Mkdir(oslDirectoryPath, os.ModePerm)
		if err != nil {
			return errors.Tracef(
				"failed to create osl directory with error: %s",
				common.RedactFilePathsError(err, oslDirectoryPath))
		}
	}

	if config.ClientVersion == "" {
		config.ClientVersion = "0"
	}

	if config.TunnelPoolSize == 0 {
		config.TunnelPoolSize = TUNNEL_POOL_SIZE
	}

	// Validate config fields.

	if !common.FileExists(config.DataRootDirectory) {
		return errors.TraceNew("DataRootDirectory does not exist")
	}

	if config.PropagationChannelId == "" {
		return errors.TraceNew("propagation channel ID is missing from the configuration file")
	}
	if config.SponsorId == "" {
		return errors.TraceNew("sponsor ID is missing from the configuration file")
	}

	_, err = strconv.Atoi(config.ClientVersion)
	if err != nil {
		return errors.Tracef("invalid client version: %s", err)
	}

	if config.TargetAPIProtocol != "" &&
		!protocol.PsiphonAPIProtocolIsValid(config.TargetAPIProtocol) {

		return errors.TraceNew("invalid TargetAPIProtocol")
	}

	if config.TargetAPIEncoding != "" &&
		!protocol.PsiphonAPIEncodingIsValid(config.TargetAPIEncoding) {

		return errors.TraceNew("invalid TargetAPIEncoding")
	}

	if !config.DisableRemoteServerListFetcher {

		if config.RemoteServerListURLs != nil {
			if config.RemoteServerListSignaturePublicKey == "" {
				return errors.TraceNew("missing RemoteServerListSignaturePublicKey")
			}
		}

		if config.ObfuscatedServerListRootURLs != nil {
			if config.RemoteServerListSignaturePublicKey == "" {
				return errors.TraceNew("missing RemoteServerListSignaturePublicKey")
			}
		}
	}

	if config.EnableUpgradeDownload {
		if len(config.UpgradeDownloadURLs) == 0 {
			return errors.TraceNew("missing UpgradeDownloadURLs")
		}
		if config.UpgradeDownloadClientVersionHeader == "" {
			return errors.TraceNew("missing UpgradeDownloadClientVersionHeader")
		}
	}

	if config.EnableFeedbackUpload {
		if len(config.FeedbackUploadURLs) == 0 {
			return errors.TraceNew("missing FeedbackUploadURLs")
		}
		if config.FeedbackEncryptionPublicKey == "" {
			return errors.TraceNew("missing FeedbackEncryptionPublicKey")
		}
	}

	if config.ObfuscatedSSHAlgorithms != nil &&
		len(config.ObfuscatedSSHAlgorithms) != 4 {
		// TODO: validate each algorithm?
		return errors.TraceNew("invalid ObfuscatedSSHAlgorithms")
	}

	if config.InproxyEnableProxy {

		if config.InproxyMaxClients <= 0 {
			return errors.TraceNew("invalid InproxyMaxClients")
		}

		if config.InproxyReducedStartTime != "" ||
			config.InproxyReducedEndTime != "" ||
			config.InproxyReducedMaxClients > 0 {

			startMinute, err := common.ParseTimeOfDayMinutes(config.InproxyReducedStartTime)
			if err != nil {
				return errors.Tracef("invalid InproxyReducedStartTime: %v", err)
			}

			endMinute, err := common.ParseTimeOfDayMinutes(config.InproxyReducedEndTime)
			if err != nil {
				return errors.Tracef("invalid InproxyReducedEndTime: %v", err)
			}

			// Reduced all day is not a valid configuration.
			if startMinute == endMinute {
				return errors.TraceNew("invalid InproxyReducedStartTime/InproxyReducedEndTime")
			}

			if config.InproxyReducedMaxClients <= 0 ||
				config.InproxyReducedMaxClients > config.InproxyMaxClients {
				return errors.TraceNew("invalid InproxyReducedMaxClients")
			}

			// InproxyReducedLimitUpstream/DownstreamBytesPerSecond don't necessarily
			// need to be less than InproxyLimitUpstream/DownstreamBytesPerSecond.

			if config.InproxyReducedLimitUpstreamBytesPerSecond == 0 {
				config.InproxyReducedLimitUpstreamBytesPerSecond = config.InproxyLimitUpstreamBytesPerSecond
			}
			if config.InproxyReducedLimitDownstreamBytesPerSecond == 0 {
				config.InproxyReducedLimitDownstreamBytesPerSecond = config.InproxyLimitDownstreamBytesPerSecond
			}
		}
	}

	if !config.DisableTunnels &&
		config.InproxyEnableProxy &&
		!GetAllowOverlappingPersonalCompartmentIDs() &&
		len(config.InproxyProxyPersonalCompartmentID) > 0 &&
		config.InproxyProxyPersonalCompartmentID ==
			config.InproxyClientPersonalCompartmentID {

		// Don't allow an in-proxy client and proxy run in the same app to match.
		return errors.TraceNew("invalid overlapping personal compartment IDs")
	}

	if len(config.InproxyProxyPersonalCompartmentID) > 0 &&
		!inproxy.Enabled() {

		// When in-proxy personal pairing mode is on, fail if the build was
		// made without the PSIPHON_ENABLE_INPROXY build tag.
		//
		// Note that this check could also be enforced in the case of a
		// LimitTunnelProtocols.IsOnlyInproxyTunnelProtocols configuration,
		// but that can be overridden by tactics so we allow it.
		return errors.TraceNew("build does not enable required in-proxy functionality")
	}

	// This constraint is expected by logic in Controller.runTunnels().

	if config.PacketTunnelTunFileDescriptor > 0 && config.TunnelPoolSize != 1 {
		return errors.TraceNew("packet tunnel mode requires TunnelPoolSize to be 1")
	}

	// SessionID must be PSIPHON_API_CLIENT_SESSION_ID_LENGTH lowercase hex-encoded bytes.

	if config.SessionID == "" {
		sessionID, err := MakeSessionId()
		if err != nil {
			return errors.Trace(err)
		}
		config.SessionID = sessionID
	}

	if len(config.SessionID) != 2*protocol.PSIPHON_API_CLIENT_SESSION_ID_LENGTH ||
		-1 != strings.IndexFunc(config.SessionID, func(c rune) bool {
			return !unicode.Is(unicode.ASCII_Hex_Digit, c) || unicode.IsUpper(c)
		}) {
		return errors.TraceNew("invalid SessionID")
	}

	config.paramsMutex.Lock()
	config.params, err = parameters.NewParameters(
		func(err error) {
			NoticeWarning("Parameters getValue failed: %s", err)
		})
	config.paramsMutex.Unlock()
	if err != nil {
		return errors.Trace(err)
	}

	// parameters.Parameters.Set will validate the config fields applied to
	// parameters.Parameters.

	err = config.SetParameters("", false, nil)
	if err != nil {
		return errors.Trace(err)
	}

	// Calculate and set the dial parameters hash. After this point, related
	// config fields must not change.

	config.setDialParametersHash()

	// Set defaults for dynamic config fields.

	config.SetDynamicConfig(config.SponsorId, config.Authorizations)

	// Initialize config.deviceBinder and config.config.networkIDGetter. These
	// wrap config.DeviceBinder and config.NetworkIDGetter/NetworkID with
	// loggers.
	//
	// The network ID getter is further wrapped with a cache (see
	// cachingNetworkIDGetter doc).
	//
	// New variables are set to avoid mutating input config fields.
	// Internally, code must use config.deviceBinder and
	// config.networkIDGetter and not the input/exported fields.

	if config.DeviceBinder != nil {
		config.deviceBinder = newLoggingDeviceBinder(config.DeviceBinder)
	}

	networkIDGetter := config.NetworkIDGetter

	if networkIDGetter == nil {
		if networkid.Enabled() {
			networkIDGetter = newCommonNetworkIDGetter()
		} else {
			// Limitation: unlike NetworkIDGetter, which calls back to platform APIs
			// this method of network identification is not dynamic and will not reflect
			// network changes that occur while running.
			if config.NetworkID != "" {
				networkIDGetter = newStaticNetworkIDGetter(config.NetworkID)
			} else {
				networkIDGetter = newStaticNetworkIDGetter(unknownNetworkID)
			}
		}
	}

	config.networkIDGetter = newCachingNetworkIDGetter(
		config,
		newLoggingNetworkIDGetter(networkIDGetter))

	// Initialize config.clientFeatures, which adds feature names on top of
	// those specified by the host application in config.ClientFeatures.

	config.clientFeatures = config.ClientFeatures

	feature := "VPN"
	if config.DeviceBinder != nil && !common.Contains(config.clientFeatures, feature) {
		config.clientFeatures = append(config.clientFeatures, feature)
	}

	// Migrate from old config fields. This results in files being moved under
	// a config specified data root directory.
	if migrateFromLegacyFields && needMigration {

		// If unset, set MigrateDataStoreDirectory to the previous default value for
		// DataStoreDirectory to ensure that datastore files are migrated.
		if config.MigrateDataStoreDirectory == "" {
			wd, err := os.Getwd()
			if err != nil {
				return errors.Trace(err)
			}
			NoticeInfo("MigrateDataStoreDirectory unset, using working directory")
			config.MigrateDataStoreDirectory = wd
		}

		// Move files that exist at legacy file paths under the data root
		// directory.

		migrations, err := migrationsFromLegacyFilePaths(config)
		if err != nil {
			return errors.Trace(err)
		}

		// Do migrations

		successfulMigrations := 0
		for _, migration := range migrations {
			err := DoFileMigration(migration)
			if err != nil {
				NoticeWarning("Config migration: %s", errors.Trace(err))
			} else {
				successfulMigrations += 1
			}
		}
		NoticeInfo(fmt.Sprintf(
			"Config migration: %d/%d legacy files successfully migrated",
			successfulMigrations, len(migrations)))

		// Remove OSL directory if empty
		if config.MigrateObfuscatedServerListDownloadDirectory != "" {
			files, err := ioutil.ReadDir(config.MigrateObfuscatedServerListDownloadDirectory)
			if err != nil {
				NoticeWarning(
					"Error reading OSL directory: %s",
					errors.Trace(common.RedactFilePathsError(err, config.MigrateObfuscatedServerListDownloadDirectory)))
			} else if len(files) == 0 {
				err := os.Remove(config.MigrateObfuscatedServerListDownloadDirectory)
				if err != nil {
					NoticeWarning(
						"Error deleting empty OSL directory: %s",
						errors.Trace(common.RedactFilePathsError(err, config.MigrateObfuscatedServerListDownloadDirectory)))
				}
			}
		}

		f, err := os.Create(migrationCompleteFilePath)
		if err != nil {
			NoticeWarning(
				"Config migration: failed to create migration completed file with error %s",
				errors.Trace(common.RedactFilePathsError(err, migrationCompleteFilePath)))
		} else {
			NoticeInfo("Config migration: completed")
			f.Close()
		}
	}

	config.committed = true

	return nil
}

// GetParameters returns the current parameters.Parameters.
func (config *Config) GetParameters() *parameters.Parameters {
	config.paramsMutex.Lock()
	defer config.paramsMutex.Unlock()

	return config.params
}

// SetParameters resets the parameters.Parameters to the default values,
// applies any config file values, and then applies the input parameters (from
// tactics, etc.)
//
// Set skipOnError to false when initially applying only config values, as
// this will validate the values and should fail. Set skipOnError to true when
// applying tactics to ignore invalid or unknown parameter values from tactics.
//
// In the case of applying tactics, do not call Config.parameters.Set
// directly as this will not first apply config values.
//
// If there is an error, the existing Config.parameters are left
// entirely unmodified.
func (config *Config) SetParameters(
	tag string, skipOnError bool, applyParameters map[string]interface{}) error {

	setParameters := []map[string]interface{}{config.makeConfigParameters()}
	if applyParameters != nil {
		setParameters = append(setParameters, applyParameters)
	}

	// Don't hold the lock on config.paramsMutex when signalling
	// GetTacticsAppliedReceivers, or else GetParameters will deadlock.
	// Releasing the lock early here also ensures we don't hold the lock when
	// posting notices.

	config.paramsMutex.Lock()
	tagUnchanged := tag != "" && tag == config.params.Get().Tag()
	validationFlags := 0
	if skipOnError {
		validationFlags |= parameters.ValidationSkipOnError
	}
	counts, err := config.params.Set(tag, validationFlags, setParameters...)
	if err != nil {
		config.paramsMutex.Unlock()
		return errors.Trace(err)
	}
	p := config.params.Get()
	config.paramsMutex.Unlock()

	// Skip emitting notices and invoking GetTacticsAppliedReceivers when the
	// tactics tag is unchanged. The notices are redundant, and the receivers
	// will unnecessarily reset components such as in-proxy broker clients.
	//
	// At this time, the GetTactics call in launchEstablishing can result in
	// redundant SetParameters calls with an unchanged tag.
	//
	// As a fail safe, and since there should not be any unwanted side
	// effects, the above params.Set is still executed even for unchanged tags.

	if tagUnchanged {
		return nil
	}

	NoticeInfo("applied %v parameters with tag '%s'", counts, tag)

	// Emit certain individual parameter values for quick reference in diagnostics.
	NoticeInfo(
		"NetworkLatencyMultiplier Min/Max/Lambda: %f/%f/%f",
		p.Float(parameters.NetworkLatencyMultiplierMin),
		p.Float(parameters.NetworkLatencyMultiplierMax),
		p.Float(parameters.NetworkLatencyMultiplierLambda))

	// Application Parameters are feature flags/config info, delivered as Client
	// Parameters via tactics/etc., to be communicated to the outer application.
	// Emit these now, as notices.
	//
	// Only emit when tactics are received (applyParameters != nil), to avoid
	// triggering the outer application with empty Application Parameters via
	// the SetParameters call from Commit.
	if applyParameters != nil {
		NoticeApplicationParameters(p.KeyValues(parameters.ApplicationParameters))
	}

	// Signal all registered TacticsAppliedReceivers that new tactics have
	// been applied. Each receiver is responsible for checking if its
	// individual tactics parameters have actually changed.
	for _, receiver := range config.GetTacticsAppliedReceivers() {
		err := receiver.TacticsApplied()
		if err != nil {
			NoticeError("TacticsApplied failed: %v", errors.Trace(err))
			// Log and continue running.
		}
	}

	return nil
}

// SetResolver sets the current resolver.
func (config *Config) SetResolver(resolver *resolver.Resolver) {
	config.resolverMutex.Lock()
	defer config.resolverMutex.Unlock()
	config.resolver = resolver
}

// GetResolver returns the current resolver. May return nil.
func (config *Config) GetResolver() *resolver.Resolver {
	config.resolverMutex.Lock()
	defer config.resolverMutex.Unlock()
	return config.resolver
}

// SetTacticsAppliedReceivers registers the list of TacticsAppliedReceivers.
func (config *Config) SetTacticsAppliedReceivers(receivers []TacticsAppliedReceiver) {
	config.tacticsAppliedReceiversMutex.Lock()
	defer config.tacticsAppliedReceiversMutex.Unlock()
	config.tacticsAppliedReceivers = receivers
}

// GetTacticsAppliedReceivers gets the list of registered
// TacticsAppliedReceivers.
func (config *Config) GetTacticsAppliedReceivers() []TacticsAppliedReceiver {
	config.tacticsAppliedReceiversMutex.Lock()
	defer config.tacticsAppliedReceiversMutex.Unlock()
	return config.tacticsAppliedReceivers
}

// SetDynamicConfig sets the current client sponsor ID and authorizations.
// Invalid values for sponsor ID are ignored. The caller must not modify the
// input authorizations slice.
func (config *Config) SetDynamicConfig(sponsorID string, authorizations []string) {
	config.dynamicConfigMutex.Lock()
	defer config.dynamicConfigMutex.Unlock()
	if sponsorID != "" {
		config.sponsorID = sponsorID
	}
	config.authorizations = authorizations
}

// GetSponsorID returns the current client sponsor ID.
func (config *Config) GetSponsorID() string {
	config.dynamicConfigMutex.Lock()
	defer config.dynamicConfigMutex.Unlock()
	return config.sponsorID
}

// IsSplitTunnelEnabled indicates if split tunnel mode is enabled, either for
// the client's own country, a specified list of countries, or both.
func (config *Config) IsSplitTunnelEnabled() bool {
	return config.SplitTunnelOwnRegion || len(config.SplitTunnelRegions) > 0
}

// GetAuthorizations returns the current client authorizations.
// The caller must not modify the returned slice.
func (config *Config) GetAuthorizations() []string {
	config.dynamicConfigMutex.Lock()
	defer config.dynamicConfigMutex.Unlock()
	return config.authorizations
}

// GetPsiphonDataDirectory returns the directory under which all persistent
// files should be stored. This directory is created under
// config.DataRootDirectory. The motivation for an additional directory is that
// config.DataRootDirectory defaults to the current working directory, which may
// include non-tunnel-core files that should be excluded from directory-spanning
// operations (e.g. excluding all tunnel-core files from backup).
func (config *Config) GetPsiphonDataDirectory() string {
	return filepath.Join(config.DataRootDirectory, PsiphonDataDirectoryName)
}

// GetHomePageFilename the path where the homepage notices file will be created.
func (config *Config) GetHomePageFilename() string {
	return filepath.Join(config.GetPsiphonDataDirectory(), HomepageFilename)
}

// GetNoticesFilename returns the path where the notices file will be created.
// When the file is rotated it will be moved to config.GetOldNoticesFilename().
func (config *Config) GetNoticesFilename() string {
	return filepath.Join(config.GetPsiphonDataDirectory(), NoticesFilename)
}

// GetOldNoticeFilename returns the path where the rotated notices file will be
// created.
func (config *Config) GetOldNoticesFilename() string {
	return filepath.Join(config.GetPsiphonDataDirectory(), OldNoticesFilename)
}

// GetDataStoreDirectory returns the directory in which the persistent database
// will be stored. Created in Config.Commit(). The persistent database contains
// information such as server entries.
func (config *Config) GetDataStoreDirectory() string {
	return filepath.Join(config.GetPsiphonDataDirectory(), "datastore")
}

// GetObfuscatedServerListDownloadDirectory returns the directory in which
// obfuscated remote server list downloads will be stored. Created in
// Config.Commit().
func (config *Config) GetObfuscatedServerListDownloadDirectory() string {
	return filepath.Join(config.GetPsiphonDataDirectory(), "osl")
}

// GetRemoteServerListDownloadFilename returns the filename where the remote
// server list download will be stored. Data is stored in co-located files
// (RemoteServerListDownloadFilename.part*) to allow for resumable downloading.
func (config *Config) GetRemoteServerListDownloadFilename() string {
	return filepath.Join(config.GetPsiphonDataDirectory(), "remote_server_list")
}

// GetUpgradeDownloadFilename specifies the filename where upgrade downloads
// will be stored. This filename is valid when UpgradeDownloadURLs
// (or UpgradeDownloadUrl) is specified. Data is stored in co-located files
// (UpgradeDownloadFilename.part*) to allow for resumable downloading.
func (config *Config) GetUpgradeDownloadFilename() string {
	return filepath.Join(config.GetPsiphonDataDirectory(), UpgradeDownloadFilename)
}

// UseUpstreamProxy indicates if an upstream proxy has been
// configured.
func (config *Config) UseUpstreamProxy() bool {
	return config.UpstreamProxyURL != ""
}

// GetNetworkID returns the current network ID. When NetworkIDGetter
// is set, this calls into the host application; otherwise, a default
// value is returned.
func (config *Config) GetNetworkID() string {
	return config.networkIDGetter.GetNetworkID()
}

func (config *Config) SetSignalComponentFailure(signalComponentFailure func()) {
	config.signalComponentFailure.Store(signalComponentFailure)
}

// IsInproxyClientPersonalPairingMode indicates that the client is in in-proxy
// personal pairing mode, where connections are made only through in-proxy
// proxies with the corresponding personal compartment ID.
func (config *Config) IsInproxyClientPersonalPairingMode() bool {
	return len(config.InproxyClientPersonalCompartmentID) > 0
}

// IsInproxyProxyPersonalPairingMode indicates that the proxy is in in-proxy
// personal pairing mode, where connections are made only with in-proxy
// clients with the corresponding personal compartment ID.
func (config *Config) IsInproxyProxyPersonalPairingMode() bool {
	return len(config.InproxyProxyPersonalCompartmentID) > 0
}

// OnInproxyMustUpgrade is invoked when the in-proxy broker returns the
// MustUpgrade response. When either running a proxy, or when running a
// client in personal-pairing mode -- two states that require in-proxy
// functionality -- onInproxyMustUpgrade initiates a shutdown after emitting
// the InproxyMustUpgrade notice.
func (config *Config) OnInproxyMustUpgrade() {

	// TODO: check if LimitTunnelProtocols is set to allow only INPROXY tunnel
	// protocols; this is another case where in-proxy functionality is
	// required.

	if config.InproxyEnableProxy || config.IsInproxyClientPersonalPairingMode() {
		if atomic.CompareAndSwapInt32(&config.inproxyMustUpgradePosted, 0, 1) {
			NoticeInproxyMustUpgrade()
		}
		config.signalComponentFailure.Load().(func())()
	}
}

func (config *Config) SetServerEntryIterationMetricsUpdater(
	updater func(movedToFront int)) {

	config.serverEntryIterationMetricsUpdater.Store(updater)
}

func (config *Config) GetServerEntryIterationMetricsUpdater() func(movedToFront int) {
	updater := config.serverEntryIterationMetricsUpdater.Load()
	if updater != nil {
		return updater.(func(int))
	}
	return nil
}

func (config *Config) makeConfigParameters() map[string]interface{} {

	// Build set of config values to apply to parameters.
	//
	// Note: names of some config fields such as
	// StaggerConnectionWorkersMilliseconds and LimitMeekBufferSizes have
	// changed in the parameters. The existing config fields are retained for
	// backwards compatibility.

	applyParameters := make(map[string]interface{})

	// To support platform clients that configure NetworkLatencyMultiplier, set
	// the NetworkLatencyMultiplierMin/NetworkLatencyMultiplierMax range to the
	// specified value. Also set the older NetworkLatencyMultiplier tactic, since
	// that will be used in the case of replaying with dial parameters persisted
	// by an older client version.
	if config.NetworkLatencyMultiplier > 0.0 {
		applyParameters[parameters.NetworkLatencyMultiplier] = config.NetworkLatencyMultiplier
		applyParameters[parameters.NetworkLatencyMultiplierMin] = config.NetworkLatencyMultiplier
		applyParameters[parameters.NetworkLatencyMultiplierMax] = config.NetworkLatencyMultiplier
	}

	if config.NetworkLatencyMultiplierMin > 0.0 {
		applyParameters[parameters.NetworkLatencyMultiplierMin] = config.NetworkLatencyMultiplierMin
	}

	if config.NetworkLatencyMultiplierMax > 0.0 {
		applyParameters[parameters.NetworkLatencyMultiplierMax] = config.NetworkLatencyMultiplierMax
	}

	if config.NetworkLatencyMultiplierLambda > 0.0 {
		applyParameters[parameters.NetworkLatencyMultiplierLambda] = config.NetworkLatencyMultiplierLambda
	}

	if len(config.LimitTunnelProtocols) > 0 {
		applyParameters[parameters.LimitTunnelProtocols] = protocol.TunnelProtocols(config.LimitTunnelProtocols)
	}

	if len(config.InitialLimitTunnelProtocols) > 0 && config.InitialLimitTunnelProtocolsCandidateCount > 0 {
		applyParameters[parameters.InitialLimitTunnelProtocols] = protocol.TunnelProtocols(config.InitialLimitTunnelProtocols)
		applyParameters[parameters.InitialLimitTunnelProtocolsCandidateCount] = config.InitialLimitTunnelProtocolsCandidateCount
	}

	if len(config.LimitTLSProfiles) > 0 {
		applyParameters[parameters.LimitTLSProfiles] = protocol.TunnelProtocols(config.LimitTLSProfiles)
	}

	if len(config.LimitQUICVersions) > 0 {
		applyParameters[parameters.LimitQUICVersions] = protocol.QUICVersions(config.LimitQUICVersions)
	}

	if config.EstablishTunnelTimeoutSeconds != nil {
		applyParameters[parameters.EstablishTunnelTimeout] = fmt.Sprintf("%ds", *config.EstablishTunnelTimeoutSeconds)
	}

	if config.EstablishTunnelServerAffinityGracePeriodMilliseconds != nil {
		applyParameters[parameters.EstablishTunnelServerAffinityGracePeriod] = fmt.Sprintf("%dms", *config.EstablishTunnelServerAffinityGracePeriodMilliseconds)
	}

	if config.EstablishTunnelPausePeriodSeconds != nil {
		applyParameters[parameters.EstablishTunnelPausePeriod] = fmt.Sprintf("%ds", *config.EstablishTunnelPausePeriodSeconds)
	}

	if config.ConnectionWorkerPoolSize != 0 {
		applyParameters[parameters.ConnectionWorkerPoolSize] = config.ConnectionWorkerPoolSize
	}

	if config.TunnelPoolSize != 0 {
		applyParameters[parameters.TunnelPoolSize] = config.TunnelPoolSize
	}

	if config.StaggerConnectionWorkersMilliseconds > 0 {
		applyParameters[parameters.StaggerConnectionWorkersPeriod] = fmt.Sprintf("%dms", config.StaggerConnectionWorkersMilliseconds)
	}

	if config.LimitIntensiveConnectionWorkers > 0 {
		applyParameters[parameters.LimitIntensiveConnectionWorkers] = config.LimitIntensiveConnectionWorkers
	}

	applyParameters[parameters.MeekLimitBufferSizes] = config.LimitMeekBufferSizes

	applyParameters[parameters.IgnoreHandshakeStatsRegexps] = config.IgnoreHandshakeStatsRegexps

	if config.EstablishTunnelTimeoutSeconds != nil {
		applyParameters[parameters.EstablishTunnelTimeout] = fmt.Sprintf("%ds", *config.EstablishTunnelTimeoutSeconds)
	}

	if config.FetchRemoteServerListRetryPeriodMilliseconds != nil {
		applyParameters[parameters.FetchRemoteServerListRetryPeriod] = fmt.Sprintf("%dms", *config.FetchRemoteServerListRetryPeriodMilliseconds)
	}

	if config.FetchUpgradeRetryPeriodMilliseconds != nil {
		applyParameters[parameters.FetchUpgradeRetryPeriod] = fmt.Sprintf("%dms", *config.FetchUpgradeRetryPeriodMilliseconds)
	}

	if !config.DisableRemoteServerListFetcher {

		if config.RemoteServerListURLs != nil {
			applyParameters[parameters.RemoteServerListSignaturePublicKey] = config.RemoteServerListSignaturePublicKey
			applyParameters[parameters.RemoteServerListURLs] = config.RemoteServerListURLs
		}

		if config.ObfuscatedServerListRootURLs != nil {
			applyParameters[parameters.RemoteServerListSignaturePublicKey] = config.RemoteServerListSignaturePublicKey
			applyParameters[parameters.ObfuscatedServerListRootURLs] = config.ObfuscatedServerListRootURLs
		}

	}

	if config.EnableUpgradeDownload {
		applyParameters[parameters.UpgradeDownloadURLs] = config.UpgradeDownloadURLs
		applyParameters[parameters.UpgradeDownloadClientVersionHeader] = config.UpgradeDownloadClientVersionHeader
	}

	if config.EnableFeedbackUpload {
		applyParameters[parameters.FeedbackUploadURLs] = config.FeedbackUploadURLs
		applyParameters[parameters.FeedbackEncryptionPublicKey] = config.FeedbackEncryptionPublicKey
	}

	if config.RateLimits != nil {
		applyParameters[parameters.TunnelRateLimits] = *config.RateLimits
	}

	if config.TransformHostNameProbability != nil {
		applyParameters[parameters.TransformHostNameProbability] = *config.TransformHostNameProbability
	}

	if config.FragmentorProbability != nil {
		applyParameters[parameters.FragmentorProbability] = *config.FragmentorProbability
	}

	if len(config.FragmentorLimitProtocols) > 0 {
		applyParameters[parameters.FragmentorLimitProtocols] = protocol.TunnelProtocols(config.FragmentorLimitProtocols)
	}

	if config.FragmentorMinTotalBytes != nil {
		applyParameters[parameters.FragmentorMinTotalBytes] = *config.FragmentorMinTotalBytes
	}

	if config.FragmentorMaxTotalBytes != nil {
		applyParameters[parameters.FragmentorMaxTotalBytes] = *config.FragmentorMaxTotalBytes
	}

	if config.FragmentorMinWriteBytes != nil {
		applyParameters[parameters.FragmentorMinWriteBytes] = *config.FragmentorMinWriteBytes
	}

	if config.FragmentorMaxWriteBytes != nil {
		applyParameters[parameters.FragmentorMaxWriteBytes] = *config.FragmentorMaxWriteBytes
	}

	if config.FragmentorMinDelayMicroseconds != nil {
		applyParameters[parameters.FragmentorMinDelay] = fmt.Sprintf("%dus", *config.FragmentorMinDelayMicroseconds)
	}

	if config.FragmentorMaxDelayMicroseconds != nil {
		applyParameters[parameters.FragmentorMaxDelay] = fmt.Sprintf("%dus", *config.FragmentorMaxDelayMicroseconds)
	}

	if config.MeekTrafficShapingProbability != nil {
		applyParameters[parameters.MeekTrafficShapingProbability] = *config.MeekTrafficShapingProbability
	}

	if len(config.MeekTrafficShapingLimitProtocols) > 0 {
		applyParameters[parameters.MeekTrafficShapingLimitProtocols] = protocol.TunnelProtocols(config.MeekTrafficShapingLimitProtocols)
	}

	if config.MeekMinTLSPadding != nil {
		applyParameters[parameters.MeekMinTLSPadding] = *config.MeekMinTLSPadding
	}

	if config.MeekMaxTLSPadding != nil {
		applyParameters[parameters.MeekMaxTLSPadding] = *config.MeekMaxTLSPadding
	}

	if config.MeekMinLimitRequestPayloadLength != nil {
		applyParameters[parameters.MeekMinLimitRequestPayloadLength] = *config.MeekMinLimitRequestPayloadLength
	}

	if config.MeekMaxLimitRequestPayloadLength != nil {
		applyParameters[parameters.MeekMaxLimitRequestPayloadLength] = *config.MeekMaxLimitRequestPayloadLength
	}

	if config.MeekRedialTLSProbability != nil {
		applyParameters[parameters.MeekRedialTLSProbability] = *config.MeekRedialTLSProbability
	}

	if config.MeekAlternateCookieNameProbability != nil {
		applyParameters[parameters.MeekAlternateCookieNameProbability] = *config.MeekAlternateCookieNameProbability
	}

	if config.MeekAlternateContentTypeProbability != nil {
		applyParameters[parameters.MeekAlternateContentTypeProbability] = *config.MeekAlternateContentTypeProbability
	}

	if config.ObfuscatedSSHMinPadding != nil {
		applyParameters[parameters.ObfuscatedSSHMinPadding] = *config.ObfuscatedSSHMinPadding
	}

	if config.ObfuscatedSSHMaxPadding != nil {
		applyParameters[parameters.ObfuscatedSSHMaxPadding] = *config.ObfuscatedSSHMaxPadding
	}

	if len(config.InitialLivenessTest) > 0 {
		applyParameters[parameters.InitialLivenessTest] = config.InitialLivenessTest
	}

	if len(config.LivenessTest) > 0 {
		applyParameters[parameters.LivenessTest] = config.LivenessTest
	}

	if config.LivenessTestMinUpstreamBytes != nil {
		applyParameters[parameters.LivenessTestMinUpstreamBytes] = *config.LivenessTestMinUpstreamBytes
	}

	if config.LivenessTestMaxUpstreamBytes != nil {
		applyParameters[parameters.LivenessTestMaxUpstreamBytes] = *config.LivenessTestMaxUpstreamBytes
	}

	if config.LivenessTestMinDownstreamBytes != nil {
		applyParameters[parameters.LivenessTestMinDownstreamBytes] = *config.LivenessTestMinDownstreamBytes
	}

	if config.LivenessTestMaxDownstreamBytes != nil {
		applyParameters[parameters.LivenessTestMaxDownstreamBytes] = *config.LivenessTestMaxDownstreamBytes
	}

	if config.ReplayCandidateCount != nil {
		applyParameters[parameters.ReplayCandidateCount] = *config.ReplayCandidateCount
	}

	if config.ReplayDialParametersTTLSeconds != nil {
		applyParameters[parameters.ReplayDialParametersTTL] = fmt.Sprintf("%ds", *config.ReplayDialParametersTTLSeconds)
	}

	if config.ReplayTargetUpstreamBytes != nil {
		applyParameters[parameters.ReplayTargetUpstreamBytes] = *config.ReplayTargetUpstreamBytes
	}

	if config.ReplayTargetDownstreamBytes != nil {
		applyParameters[parameters.ReplayTargetDownstreamBytes] = *config.ReplayTargetDownstreamBytes
	}

	if config.ReplayTargetTunnelDurationSeconds != nil {
		applyParameters[parameters.ReplayTargetTunnelDuration] = fmt.Sprintf("%ds", *config.ReplayTargetTunnelDurationSeconds)
	}

	if config.ReplayLaterRoundMoveToFrontProbability != nil {
		applyParameters[parameters.ReplayLaterRoundMoveToFrontProbability] = *config.ReplayLaterRoundMoveToFrontProbability
	}

	if config.ReplayRetainFailedProbability != nil {
		applyParameters[parameters.ReplayRetainFailedProbability] = *config.ReplayRetainFailedProbability
	}

	if config.ReplayIgnoreChangedConfigStateProbability != nil {
		applyParameters[parameters.ReplayIgnoreChangedConfigStateProbability] = *config.ReplayIgnoreChangedConfigStateProbability
	}

	if config.UseOnlyCustomTLSProfiles != nil {
		applyParameters[parameters.UseOnlyCustomTLSProfiles] = *config.UseOnlyCustomTLSProfiles
	}

	if len(config.CustomTLSProfiles) > 0 {
		applyParameters[parameters.CustomTLSProfiles] = config.CustomTLSProfiles
	}

	if config.SelectRandomizedTLSProfileProbability != nil {
		applyParameters[parameters.SelectRandomizedTLSProfileProbability] = *config.SelectRandomizedTLSProfileProbability
	}

	if config.NoDefaultTLSSessionIDProbability != nil {
		applyParameters[parameters.NoDefaultTLSSessionIDProbability] = *config.NoDefaultTLSSessionIDProbability
	}

	if len(config.DisableFrontingProviderTLSProfiles) > 0 {
		applyParameters[parameters.DisableFrontingProviderTLSProfiles] = config.DisableFrontingProviderTLSProfiles
	}

	if config.ClientBurstUpstreamTargetBytes != nil {
		applyParameters[parameters.ClientBurstUpstreamTargetBytes] = *config.ClientBurstUpstreamTargetBytes
	}

	if config.ClientBurstUpstreamDeadlineMilliseconds != nil {
		applyParameters[parameters.ClientBurstUpstreamDeadline] = fmt.Sprintf("%dms", *config.ClientBurstUpstreamDeadlineMilliseconds)
	}

	if config.ClientBurstDownstreamTargetBytes != nil {
		applyParameters[parameters.ClientBurstDownstreamTargetBytes] = *config.ClientBurstDownstreamTargetBytes
	}

	if config.ClientBurstDownstreamDeadlineMilliseconds != nil {
		applyParameters[parameters.ClientBurstDownstreamDeadline] = fmt.Sprintf("%dms", *config.ClientBurstDownstreamDeadlineMilliseconds)
	}

	if config.CustomHostNameRegexes != nil {
		applyParameters[parameters.CustomHostNameRegexes] = parameters.RegexStrings(config.CustomHostNameRegexes)
	}

	if config.CustomHostNameProbability != nil {
		applyParameters[parameters.CustomHostNameProbability] = *config.CustomHostNameProbability
	}

	if config.CustomHostNameLimitProtocols != nil {
		applyParameters[parameters.CustomHostNameLimitProtocols] = protocol.TunnelProtocols(config.CustomHostNameLimitProtocols)
	}

	if config.ConjureCachedRegistrationTTLSeconds != nil {
		applyParameters[parameters.ConjureCachedRegistrationTTL] = fmt.Sprintf("%ds", *config.ConjureCachedRegistrationTTLSeconds)
	}

	if config.ConjureAPIRegistrarBidirectionalURL != "" {
		applyParameters[parameters.ConjureAPIRegistrarBidirectionalURL] = config.ConjureAPIRegistrarBidirectionalURL
	}

	if len(config.ConjureAPIRegistrarFrontingSpecs) > 0 {
		applyParameters[parameters.ConjureAPIRegistrarFrontingSpecs] = config.ConjureAPIRegistrarFrontingSpecs
	}

	if config.ConjureAPIRegistrarMinDelayMilliseconds != nil {
		applyParameters[parameters.ConjureAPIRegistrarMinDelay] = fmt.Sprintf("%dms", *config.ConjureAPIRegistrarMinDelayMilliseconds)
	}

	if config.ConjureAPIRegistrarMaxDelayMilliseconds != nil {
		applyParameters[parameters.ConjureAPIRegistrarMaxDelay] = fmt.Sprintf("%dms", *config.ConjureAPIRegistrarMaxDelayMilliseconds)
	}

	if config.ConjureDecoyRegistrarProbability != nil {
		applyParameters[parameters.ConjureDecoyRegistrarProbability] = *config.ConjureDecoyRegistrarProbability
	}

	if config.ConjureDecoyRegistrarWidth != nil {
		applyParameters[parameters.ConjureDecoyRegistrarWidth] = *config.ConjureDecoyRegistrarWidth
	}

	if config.ConjureDecoyRegistrarMinDelayMilliseconds != nil {
		applyParameters[parameters.ConjureDecoyRegistrarMinDelay] = fmt.Sprintf("%dms", *config.ConjureDecoyRegistrarMinDelayMilliseconds)
	}

	if config.ConjureDecoyRegistrarMaxDelayMilliseconds != nil {
		applyParameters[parameters.ConjureDecoyRegistrarMaxDelay] = fmt.Sprintf("%dms", *config.ConjureDecoyRegistrarMaxDelayMilliseconds)
	}

	if config.ConjureEnableIPv6Dials != nil {
		applyParameters[parameters.ConjureEnableIPv6Dials] = *config.ConjureEnableIPv6Dials
	}

	if config.ConjureEnablePortRandomization != nil {
		applyParameters[parameters.ConjureEnablePortRandomization] = *config.ConjureEnablePortRandomization
	}

	if config.ConjureEnableRegistrationOverrides != nil {
		applyParameters[parameters.ConjureEnableRegistrationOverrides] = *config.ConjureEnableRegistrationOverrides
	}

	if config.ConjureLimitTransports != nil {
		applyParameters[parameters.ConjureLimitTransports] = config.ConjureLimitTransports
	}

	if config.ConjureSTUNServerAddresses != nil {
		applyParameters[parameters.ConjureSTUNServerAddresses] = config.ConjureSTUNServerAddresses
	}

	if config.ConjureDTLSEmptyInitialPacketProbability != nil {
		applyParameters[parameters.ConjureDTLSEmptyInitialPacketProbability] = *config.ConjureDTLSEmptyInitialPacketProbability
	}

	if config.HoldOffTunnelProtocolMinDurationMilliseconds != nil {
		applyParameters[parameters.HoldOffTunnelProtocolMinDuration] = fmt.Sprintf("%dms", *config.HoldOffTunnelProtocolMinDurationMilliseconds)
	}

	if config.HoldOffTunnelProtocolMaxDurationMilliseconds != nil {
		applyParameters[parameters.HoldOffTunnelProtocolMaxDuration] = fmt.Sprintf("%dms", *config.HoldOffTunnelProtocolMaxDurationMilliseconds)
	}

	if len(config.HoldOffTunnelProtocolNames) > 0 {
		applyParameters[parameters.HoldOffTunnelProtocolNames] = protocol.TunnelProtocols(config.HoldOffTunnelProtocolNames)
	}

	if config.HoldOffTunnelProtocolProbability != nil {
		applyParameters[parameters.HoldOffTunnelProtocolProbability] = *config.HoldOffTunnelProtocolProbability
	}

	if config.HoldOffFrontingTunnelMinDurationMilliseconds != nil {
		applyParameters[parameters.HoldOffFrontingTunnelMinDuration] = fmt.Sprintf("%dms", *config.HoldOffFrontingTunnelMinDurationMilliseconds)
	}

	if config.HoldOffFrontingTunnelMaxDurationMilliseconds != nil {
		applyParameters[parameters.HoldOffFrontingTunnelMaxDuration] = fmt.Sprintf("%dms", *config.HoldOffFrontingTunnelMaxDurationMilliseconds)
	}

	if len(config.HoldOffFrontingTunnelProviderIDs) > 0 {
		applyParameters[parameters.HoldOffFrontingTunnelProviderIDs] = config.HoldOffFrontingTunnelProviderIDs
	}

	if config.HoldOffFrontingTunnelProbability != nil {
		applyParameters[parameters.HoldOffFrontingTunnelProbability] = *config.HoldOffFrontingTunnelProbability
	}

	if config.HoldOffDirectTunnelMinDurationMilliseconds != nil {
		applyParameters[parameters.HoldOffDirectTunnelMinDuration] = fmt.Sprintf("%dms", *config.HoldOffDirectTunnelMinDurationMilliseconds)
	}

	if config.HoldOffDirectTunnelMaxDurationMilliseconds != nil {
		applyParameters[parameters.HoldOffDirectTunnelMaxDuration] = fmt.Sprintf("%dms", *config.HoldOffDirectTunnelMaxDurationMilliseconds)
	}

	if len(config.HoldOffDirectTunnelProviderRegions) > 0 {
		applyParameters[parameters.HoldOffDirectTunnelProviderRegions] = parameters.KeyStrings(config.HoldOffDirectTunnelProviderRegions)
	}

	if config.HoldOffDirectTunnelProbability != nil {
		applyParameters[parameters.HoldOffDirectTunnelProbability] = *config.HoldOffDirectTunnelProbability
	}

	if len(config.RestrictDirectProviderRegions) > 0 {
		applyParameters[parameters.RestrictDirectProviderRegions] = parameters.KeyStrings(config.RestrictDirectProviderRegions)
	}

	if config.RestrictDirectProviderIDsClientProbability != nil {
		applyParameters[parameters.RestrictDirectProviderIDsClientProbability] = *config.RestrictDirectProviderIDsClientProbability
	}

	if len(config.RestrictFrontingProviderIDs) > 0 {
		applyParameters[parameters.RestrictFrontingProviderIDs] = config.RestrictFrontingProviderIDs
	}

	if config.RestrictFrontingProviderIDsClientProbability != nil {
		applyParameters[parameters.RestrictFrontingProviderIDsClientProbability] = *config.RestrictFrontingProviderIDsClientProbability
	}

	if config.HoldOffInproxyTunnelMinDurationMilliseconds != nil {
		applyParameters[parameters.HoldOffInproxyTunnelMinDuration] = fmt.Sprintf("%dms", *config.HoldOffInproxyTunnelMinDurationMilliseconds)
	}

	if config.HoldOffInproxyTunnelMaxDurationMilliseconds != nil {
		applyParameters[parameters.HoldOffInproxyTunnelMaxDuration] = fmt.Sprintf("%dms", *config.HoldOffInproxyTunnelMaxDurationMilliseconds)
	}

	if len(config.HoldOffInproxyTunnelProviderRegions) > 0 {
		applyParameters[parameters.HoldOffInproxyTunnelProviderRegions] = parameters.KeyStrings(config.HoldOffInproxyTunnelProviderRegions)
	}

	if config.HoldOffInproxyTunnelProbability != nil {
		applyParameters[parameters.HoldOffInproxyTunnelProbability] = *config.HoldOffInproxyTunnelProbability
	}

	if config.UpstreamProxyAllowAllServerEntrySources != nil {
		applyParameters[parameters.UpstreamProxyAllowAllServerEntrySources] = *config.UpstreamProxyAllowAllServerEntrySources
	}

	if len(config.LimitTunnelDialPortNumbers) > 0 {
		applyParameters[parameters.LimitTunnelDialPortNumbers] = config.LimitTunnelDialPortNumbers
	}

	if config.QUICDialEarlyProbability != nil {
		applyParameters[parameters.QUICDialEarlyProbability] = *config.QUICDialEarlyProbability
	}

	if config.QUICObfuscatedPSKProbability != nil {
		applyParameters[parameters.QUICObfuscatedPSKProbability] = *config.QUICObfuscatedPSKProbability
	}

	if config.QUICDisablePathMTUDiscoveryProbability != nil {
		applyParameters[parameters.QUICDisableClientPathMTUDiscoveryProbability] = *config.QUICDisablePathMTUDiscoveryProbability
	}

	if config.DNSResolverAttemptsPerServer != nil {
		applyParameters[parameters.DNSResolverAttemptsPerServer] = *config.DNSResolverAttemptsPerServer
	}

	if config.DNSResolverAttemptsPerPreferredServer != nil {
		applyParameters[parameters.DNSResolverAttemptsPerPreferredServer] = *config.DNSResolverAttemptsPerPreferredServer
	}

	if config.DNSResolverRequestTimeoutMilliseconds != nil {
		applyParameters[parameters.DNSResolverRequestTimeout] = fmt.Sprintf("%dms", *config.DNSResolverRequestTimeoutMilliseconds)
	}

	if config.DNSResolverAwaitTimeoutMilliseconds != nil {
		applyParameters[parameters.DNSResolverAwaitTimeout] = fmt.Sprintf("%dms", *config.DNSResolverAwaitTimeoutMilliseconds)
	}

	if config.DNSResolverPreresolvedIPAddressProbability != nil {
		applyParameters[parameters.DNSResolverPreresolvedIPAddressProbability] = *config.DNSResolverPreresolvedIPAddressProbability
	}

	if config.DNSResolverPreresolvedIPAddressCIDRs != nil {
		applyParameters[parameters.DNSResolverPreresolvedIPAddressCIDRs] = config.DNSResolverPreresolvedIPAddressCIDRs
	}

	if config.DNSResolverAlternateServers != nil {
		applyParameters[parameters.DNSResolverAlternateServers] = config.DNSResolverAlternateServers
	}

	if config.DNSResolverPreferredAlternateServers != nil {
		applyParameters[parameters.DNSResolverPreferredAlternateServers] = config.DNSResolverPreferredAlternateServers
	}

	if config.DNSResolverPreferAlternateServerProbability != nil {
		applyParameters[parameters.DNSResolverPreferAlternateServerProbability] = *config.DNSResolverPreferAlternateServerProbability
	}

	if config.DNSResolverProtocolTransformSpecs != nil {
		applyParameters[parameters.DNSResolverProtocolTransformSpecs] = config.DNSResolverProtocolTransformSpecs
	}

	if config.DNSResolverProtocolTransformScopedSpecNames != nil {
		applyParameters[parameters.DNSResolverProtocolTransformScopedSpecNames] = config.DNSResolverProtocolTransformScopedSpecNames
	}

	if config.DNSResolverProtocolTransformProbability != nil {
		applyParameters[parameters.DNSResolverProtocolTransformProbability] = *config.DNSResolverProtocolTransformProbability
	}

	if config.DNSResolverQNameRandomizeCasingProbability != nil {
		applyParameters[parameters.DNSResolverQNameRandomizeCasingProbability] = *config.DNSResolverQNameRandomizeCasingProbability
	}

	if config.DNSResolverQNameMustMatchProbability != nil {
		applyParameters[parameters.DNSResolverQNameMustMatchProbability] = *config.DNSResolverQNameMustMatchProbability
	}

	if config.DNSResolverIncludeEDNS0Probability != nil {
		applyParameters[parameters.DNSResolverIncludeEDNS0Probability] = *config.DNSResolverIncludeEDNS0Probability
	}

	if config.DNSResolverCacheExtensionInitialTTLMilliseconds != nil {
		applyParameters[parameters.DNSResolverCacheExtensionInitialTTL] = fmt.Sprintf("%dms", *config.DNSResolverCacheExtensionInitialTTLMilliseconds)
	}

	if config.DNSResolverCacheExtensionVerifiedTTLMilliseconds != nil {
		applyParameters[parameters.DNSResolverCacheExtensionVerifiedTTL] = fmt.Sprintf("%dms", *config.DNSResolverCacheExtensionVerifiedTTLMilliseconds)
	}

	if config.DirectHTTPProtocolTransformSpecs != nil {
		applyParameters[parameters.DirectHTTPProtocolTransformSpecs] = config.DirectHTTPProtocolTransformSpecs
	}

	if config.DirectHTTPProtocolTransformScopedSpecNames != nil {
		applyParameters[parameters.DirectHTTPProtocolTransformScopedSpecNames] = config.DirectHTTPProtocolTransformScopedSpecNames
	}

	if config.DirectHTTPProtocolTransformProbability != nil {
		applyParameters[parameters.DirectHTTPProtocolTransformProbability] = *config.DirectHTTPProtocolTransformProbability
	}

	if config.FrontedHTTPProtocolTransformSpecs != nil {
		applyParameters[parameters.FrontedHTTPProtocolTransformSpecs] = config.FrontedHTTPProtocolTransformSpecs
	}

	if config.FrontedHTTPProtocolTransformScopedSpecNames != nil {
		applyParameters[parameters.FrontedHTTPProtocolTransformScopedSpecNames] = config.FrontedHTTPProtocolTransformScopedSpecNames
	}

	if config.FrontedHTTPProtocolTransformProbability != nil {
		applyParameters[parameters.FrontedHTTPProtocolTransformProbability] = *config.FrontedHTTPProtocolTransformProbability
	}

	if config.OSSHObfuscatorSeedTransformSpecs != nil {
		applyParameters[parameters.OSSHObfuscatorSeedTransformSpecs] = config.OSSHObfuscatorSeedTransformSpecs
	}

	if config.OSSHObfuscatorSeedTransformScopedSpecNames != nil {
		applyParameters[parameters.OSSHObfuscatorSeedTransformScopedSpecNames] = config.OSSHObfuscatorSeedTransformScopedSpecNames
	}

	if config.OSSHObfuscatorSeedTransformProbability != nil {
		applyParameters[parameters.OSSHObfuscatorSeedTransformProbability] = *config.OSSHObfuscatorSeedTransformProbability
	}

	if config.ObfuscatedQUICNonceTransformSpecs != nil {
		applyParameters[parameters.ObfuscatedQUICNonceTransformSpecs] = config.ObfuscatedQUICNonceTransformSpecs
	}

	if config.ObfuscatedQUICNonceTransformScopedSpecNames != nil {
		applyParameters[parameters.ObfuscatedQUICNonceTransformScopedSpecNames] = config.ObfuscatedQUICNonceTransformScopedSpecNames
	}

	if config.ObfuscatedQUICNonceTransformProbability != nil {
		applyParameters[parameters.ObfuscatedQUICNonceTransformProbability] = *config.ObfuscatedQUICNonceTransformProbability
	}

	if config.OSSHPrefixSpecs != nil {
		applyParameters[parameters.OSSHPrefixSpecs] = config.OSSHPrefixSpecs
	}

	if config.OSSHPrefixScopedSpecNames != nil {
		applyParameters[parameters.OSSHPrefixScopedSpecNames] = config.OSSHPrefixScopedSpecNames
	}

	if config.OSSHPrefixProbability != nil {
		applyParameters[parameters.OSSHPrefixProbability] = *config.OSSHPrefixProbability
	}

	if config.OSSHPrefixSplitMinDelayMilliseconds != nil {
		applyParameters[parameters.OSSHPrefixSplitMinDelay] = fmt.Sprintf("%dms", *config.OSSHPrefixSplitMinDelayMilliseconds)
	}

	if config.OSSHPrefixSplitMaxDelayMilliseconds != nil {
		applyParameters[parameters.OSSHPrefixSplitMaxDelay] = fmt.Sprintf("%dms", *config.OSSHPrefixSplitMaxDelayMilliseconds)
	}

	if config.OSSHPrefixEnableFragmentor != nil {
		applyParameters[parameters.OSSHPrefixEnableFragmentor] = *config.OSSHPrefixEnableFragmentor
	}

	if config.ShadowsocksPrefixSpecs != nil {
		applyParameters[parameters.ShadowsocksPrefixSpecs] = config.ShadowsocksPrefixSpecs
	}

	if config.ShadowsocksPrefixScopedSpecNames != nil {
		applyParameters[parameters.ShadowsocksPrefixScopedSpecNames] = config.ShadowsocksPrefixScopedSpecNames
	}

	if config.ShadowsocksPrefixProbability != nil {
		applyParameters[parameters.ShadowsocksPrefixProbability] = *config.ShadowsocksPrefixProbability
	}

	if config.TLSTunnelObfuscatedPSKProbability != nil {
		applyParameters[parameters.TLSTunnelObfuscatedPSKProbability] = *config.TLSTunnelObfuscatedPSKProbability
	}

	if config.TLSTunnelTrafficShapingProbability != nil {
		applyParameters[parameters.TLSTunnelTrafficShapingProbability] = *config.TLSTunnelTrafficShapingProbability
	}

	if config.TLSTunnelMinTLSPadding != nil {
		applyParameters[parameters.TLSTunnelMinTLSPadding] = *config.TLSTunnelMinTLSPadding
	}

	if config.TLSTunnelMaxTLSPadding != nil {
		applyParameters[parameters.TLSTunnelMaxTLSPadding] = *config.TLSTunnelMaxTLSPadding
	}

	if config.TLSFragmentClientHelloProbability != nil {
		applyParameters[parameters.TLSFragmentClientHelloProbability] = *config.TLSFragmentClientHelloProbability
	}

	if len(config.TLSFragmentClientHelloLimitProtocols) > 0 {
		applyParameters[parameters.TLSFragmentClientHelloLimitProtocols] = protocol.TunnelProtocols(config.TLSFragmentClientHelloLimitProtocols)
	}

	if config.SteeringIPCacheTTLSeconds != nil {
		applyParameters[parameters.SteeringIPCacheTTL] = fmt.Sprintf("%ds", *config.SteeringIPCacheTTLSeconds)
	}

	if config.SteeringIPCacheMaxEntries != nil {
		applyParameters[parameters.SteeringIPCacheMaxEntries] = *config.SteeringIPCacheMaxEntries
	}

	if config.SteeringIPProbability != nil {
		applyParameters[parameters.SteeringIPProbability] = *config.SteeringIPProbability
	}

	if config.FrontedHTTPClientReplayDialParametersTTLSeconds != nil {
		applyParameters[parameters.FrontedHTTPClientReplayDialParametersTTL] = fmt.Sprintf("%ds", *config.FrontedHTTPClientReplayDialParametersTTLSeconds)
	}

	if config.FrontedHTTPClientReplayUpdateFrequencySeconds != nil {
		applyParameters[parameters.FrontedHTTPClientReplayUpdateFrequency] = fmt.Sprintf("%ds", *config.FrontedHTTPClientReplayUpdateFrequencySeconds)
	}

	if config.FrontedHTTPClientReplayDialParametersProbability != nil {
		applyParameters[parameters.FrontedHTTPClientReplayDialParametersProbability] = *config.FrontedHTTPClientReplayDialParametersProbability
	}

	if config.FrontedHTTPClientReplayRetainFailedProbability != nil {
		applyParameters[parameters.FrontedHTTPClientReplayRetainFailedProbability] = *config.FrontedHTTPClientReplayRetainFailedProbability
	}

	if config.InproxyPersonalPairingConnectionWorkerPoolSize != 0 {
		applyParameters[parameters.InproxyPersonalPairingConnectionWorkerPoolSize] = config.InproxyPersonalPairingConnectionWorkerPoolSize
	}

	if config.InproxyAllowProxy != nil {
		applyParameters[parameters.InproxyAllowProxy] = *config.InproxyAllowProxy
	}

	if config.InproxyAllowClient != nil {
		applyParameters[parameters.InproxyAllowClient] = *config.InproxyAllowClient
	}

	if config.InproxyTunnelProtocolSelectionProbability != nil {
		applyParameters[parameters.InproxyTunnelProtocolSelectionProbability] = *config.InproxyTunnelProtocolSelectionProbability
	}

	if len(config.InproxyBrokerSpecs) > 0 {
		applyParameters[parameters.InproxyBrokerSpecs] = config.InproxyBrokerSpecs
	}

	if len(config.InproxyPersonalPairingBrokerSpecs) > 0 {
		applyParameters[parameters.InproxyPersonalPairingBrokerSpecs] = config.InproxyPersonalPairingBrokerSpecs
	}

	if len(config.InproxyProxyBrokerSpecs) > 0 {
		applyParameters[parameters.InproxyProxyBrokerSpecs] = config.InproxyProxyBrokerSpecs
	}

	if len(config.InproxyProxyPersonalPairingBrokerSpecs) > 0 {
		applyParameters[parameters.InproxyProxyPersonalPairingBrokerSpecs] = config.InproxyProxyPersonalPairingBrokerSpecs
	}

	if len(config.InproxyClientBrokerSpecs) > 0 {
		applyParameters[parameters.InproxyClientBrokerSpecs] = config.InproxyClientBrokerSpecs
	}

	if len(config.InproxyClientPersonalPairingBrokerSpecs) > 0 {
		applyParameters[parameters.InproxyClientPersonalPairingBrokerSpecs] = config.InproxyClientPersonalPairingBrokerSpecs
	}

	if config.InproxyReplayBrokerDialParametersTTLSeconds != nil {
		applyParameters[parameters.InproxyReplayBrokerDialParametersTTL] = fmt.Sprintf("%ds", *config.InproxyReplayBrokerDialParametersTTLSeconds)
	}

	if config.InproxyReplayBrokerUpdateFrequencySeconds != nil {
		applyParameters[parameters.InproxyReplayBrokerUpdateFrequency] = fmt.Sprintf("%ds", *config.InproxyReplayBrokerUpdateFrequencySeconds)
	}

	if config.InproxyReplayBrokerDialParametersProbability != nil {
		applyParameters[parameters.InproxyReplayBrokerDialParametersProbability] = *config.InproxyReplayBrokerDialParametersProbability
	}

	if config.InproxyReplayBrokerRetainFailedProbability != nil {
		applyParameters[parameters.InproxyReplayBrokerRetainFailedProbability] = *config.InproxyReplayBrokerRetainFailedProbability
	}

	if len(config.InproxyCommonCompartmentIDs) > 0 {
		applyParameters[parameters.InproxyCommonCompartmentIDs] = config.InproxyCommonCompartmentIDs
	}

	if config.InproxyMaxCompartmentIDListLength != nil {
		applyParameters[parameters.InproxyMaxCompartmentIDListLength] = *config.InproxyMaxCompartmentIDListLength
	}

	if config.InproxyProxyAnnounceRequestTimeoutMilliseconds != nil {
		applyParameters[parameters.InproxyProxyAnnounceRequestTimeout] = fmt.Sprintf("%dms", *config.InproxyProxyAnnounceRequestTimeoutMilliseconds)
	}

	if config.InproxyProxyAnnounceDelayMilliseconds != nil {
		applyParameters[parameters.InproxyProxyAnnounceDelay] = fmt.Sprintf("%dms", *config.InproxyProxyAnnounceDelayMilliseconds)
	}

	if config.InproxyProxyAnnounceMaxBackoffDelayMilliseconds != nil {
		applyParameters[parameters.InproxyProxyAnnounceMaxBackoffDelay] = fmt.Sprintf("%dms", *config.InproxyProxyAnnounceMaxBackoffDelayMilliseconds)
	}

	if config.InproxyProxyAnnounceDelayJitter != nil {
		applyParameters[parameters.InproxyProxyAnnounceDelayJitter] = *config.InproxyProxyAnnounceDelayJitter
	}

	if config.InproxyProxyAnswerRequestTimeoutMilliseconds != nil {
		applyParameters[parameters.InproxyProxyAnswerRequestTimeout] = fmt.Sprintf("%dms", *config.InproxyProxyAnswerRequestTimeoutMilliseconds)
	}

	if config.InproxyClientOfferRequestTimeoutMilliseconds != nil {
		applyParameters[parameters.InproxyClientOfferRequestTimeout] = fmt.Sprintf("%dms", *config.InproxyClientOfferRequestTimeoutMilliseconds)
	}

	if config.InproxyClientOfferRequestPersonalTimeoutMilliseconds != nil {
		applyParameters[parameters.InproxyClientOfferRequestPersonalTimeout] = fmt.Sprintf("%dms", *config.InproxyClientOfferRequestPersonalTimeoutMilliseconds)
	}

	if config.InproxyClientOfferRetryDelayMilliseconds != nil {
		applyParameters[parameters.InproxyClientOfferRetryDelay] = fmt.Sprintf("%dms", *config.InproxyClientOfferRetryDelayMilliseconds)
	}

	if config.InproxyClientOfferRetryJitter != nil {
		applyParameters[parameters.InproxyClientOfferRetryJitter] = *config.InproxyClientOfferRetryJitter
	}

	if config.InproxyClientRelayedPacketRequestTimeoutMilliseconds != nil {
		applyParameters[parameters.InproxyClientRelayedPacketRequestTimeout] = fmt.Sprintf("%dms", *config.InproxyClientRelayedPacketRequestTimeoutMilliseconds)
	}

	if config.InproxyDTLSRandomizationProbability != nil {
		applyParameters[parameters.InproxyDTLSRandomizationProbability] = *config.InproxyDTLSRandomizationProbability
	}

	if config.InproxyWebRTCMediaStreamsProbability != nil {
		applyParameters[parameters.InproxyWebRTCMediaStreamsProbability] = *config.InproxyWebRTCMediaStreamsProbability
	}

	if config.InproxyWebRTCDataChannelTrafficShapingProbability != nil {
		applyParameters[parameters.InproxyWebRTCDataChannelTrafficShapingProbability] = *config.InproxyWebRTCDataChannelTrafficShapingProbability
	}

	if config.InproxyWebRTCDataChannelTrafficShapingParameters != nil {
		applyParameters[parameters.InproxyWebRTCDataChannelTrafficShapingParameters] = *config.InproxyWebRTCDataChannelTrafficShapingParameters
	}

	if config.InproxyWebRTCMediaStreamsTrafficShapingProbability != nil {
		applyParameters[parameters.InproxyWebRTCMediaStreamsTrafficShapingProbability] = *config.InproxyWebRTCMediaStreamsTrafficShapingProbability
	}

	if config.InproxyWebRTCMediaStreamsTrafficShapingParameters != nil {
		applyParameters[parameters.InproxyWebRTCMediaStreamsTrafficShapingParameters] = *config.InproxyWebRTCMediaStreamsTrafficShapingParameters
	}

	if len(config.InproxySTUNServerAddresses) > 0 {
		applyParameters[parameters.InproxySTUNServerAddresses] = config.InproxySTUNServerAddresses
	}

	if len(config.InproxySTUNServerAddressesRFC5780) > 0 {
		applyParameters[parameters.InproxySTUNServerAddressesRFC5780] = config.InproxySTUNServerAddressesRFC5780
	}

	if len(config.InproxyProxySTUNServerAddresses) > 0 {
		applyParameters[parameters.InproxyProxySTUNServerAddresses] = config.InproxyProxySTUNServerAddresses
	}

	if len(config.InproxyProxySTUNServerAddressesRFC5780) > 0 {
		applyParameters[parameters.InproxyProxySTUNServerAddressesRFC5780] = config.InproxyProxySTUNServerAddressesRFC5780
	}

	if len(config.InproxyClientSTUNServerAddresses) > 0 {
		applyParameters[parameters.InproxyClientSTUNServerAddresses] = config.InproxyClientSTUNServerAddresses
	}

	if len(config.InproxyClientSTUNServerAddressesRFC5780) > 0 {
		applyParameters[parameters.InproxyClientSTUNServerAddressesRFC5780] = config.InproxyClientSTUNServerAddressesRFC5780
	}

	if config.InproxyClientDiscoverNATProbability != nil {
		applyParameters[parameters.InproxyClientDiscoverNATProbability] = *config.InproxyClientDiscoverNATProbability
	}

	if config.InproxyDisableSTUN != nil {
		applyParameters[parameters.InproxyDisableSTUN] = *config.InproxyDisableSTUN
	}

	if config.InproxyDisablePortMapping != nil {
		applyParameters[parameters.InproxyDisablePortMapping] = *config.InproxyDisablePortMapping
	}

	if config.InproxyDisableInboundForMobileNetworks != nil {
		applyParameters[parameters.InproxyDisableInboundForMobileNetworks] = *config.InproxyDisableInboundForMobileNetworks
	}

	if config.InproxyDisableIPv6ICECandidates != nil {
		applyParameters[parameters.InproxyDisableIPv6ICECandidates] = *config.InproxyDisableIPv6ICECandidates
	}

	if config.InproxyProxyDisableSTUN != nil {
		applyParameters[parameters.InproxyProxyDisableSTUN] = *config.InproxyProxyDisableSTUN
	}

	if config.InproxyProxyDisablePortMapping != nil {
		applyParameters[parameters.InproxyProxyDisablePortMapping] = *config.InproxyProxyDisablePortMapping
	}

	if config.InproxyProxyDisableInboundForMobileNetworks != nil {
		applyParameters[parameters.InproxyProxyDisableInboundForMobileNetworks] = *config.InproxyProxyDisableInboundForMobileNetworks
	}

	if config.InproxyProxyDisableIPv6ICECandidates != nil {
		applyParameters[parameters.InproxyProxyDisableIPv6ICECandidates] = *config.InproxyProxyDisableIPv6ICECandidates
	}

	if config.InproxyClientDisableSTUN != nil {
		applyParameters[parameters.InproxyClientDisableSTUN] = *config.InproxyClientDisableSTUN
	}

	if config.InproxyClientDisablePortMapping != nil {
		applyParameters[parameters.InproxyClientDisablePortMapping] = *config.InproxyClientDisablePortMapping
	}

	if config.InproxyClientDisableInboundForMobileNetworks != nil {
		applyParameters[parameters.InproxyClientDisableInboundForMobileNetworks] = *config.InproxyClientDisableInboundForMobileNetworks
	}

	if config.InproxyClientDisableIPv6ICECandidates != nil {
		applyParameters[parameters.InproxyClientDisableIPv6ICECandidates] = *config.InproxyClientDisableIPv6ICECandidates
	}

	if config.InproxyProxyDiscoverNATTimeoutMilliseconds != nil {
		applyParameters[parameters.InproxyProxyDiscoverNATTimeout] = fmt.Sprintf("%dms", *config.InproxyProxyDiscoverNATTimeoutMilliseconds)
	}

	if config.InproxyClientDiscoverNATTimeoutMilliseconds != nil {
		applyParameters[parameters.InproxyClientDiscoverNATTimeout] = fmt.Sprintf("%dms", *config.InproxyClientDiscoverNATTimeoutMilliseconds)
	}

	if config.InproxyWebRTCAnswerTimeoutMilliseconds != nil {
		applyParameters[parameters.InproxyWebRTCAnswerTimeout] = fmt.Sprintf("%dms", *config.InproxyWebRTCAnswerTimeoutMilliseconds)
	}

	if config.InproxyProxyWebRTCAwaitReadyToProxyTimeoutMilliseconds != nil {
		applyParameters[parameters.InproxyProxyWebRTCAwaitReadyToProxyTimeout] = fmt.Sprintf("%dms", *config.InproxyProxyWebRTCAwaitReadyToProxyTimeoutMilliseconds)
	}

	if config.InproxyClientWebRTCAwaitReadyToProxyTimeoutMilliseconds != nil {
		applyParameters[parameters.InproxyClientWebRTCAwaitReadyToProxyTimeout] = fmt.Sprintf("%dms", *config.InproxyClientWebRTCAwaitReadyToProxyTimeoutMilliseconds)
	}

	if config.InproxyProxyDestinationDialTimeoutMilliseconds != nil {
		applyParameters[parameters.InproxyProxyDestinationDialTimeout] = fmt.Sprintf("%dms", *config.InproxyProxyDestinationDialTimeoutMilliseconds)
	}

	if config.InproxyPsiphonAPIRequestTimeoutMilliseconds != nil {
		applyParameters[parameters.InproxyPsiphonAPIRequestTimeout] = fmt.Sprintf("%dms", *config.InproxyPsiphonAPIRequestTimeoutMilliseconds)
	}

	if config.InproxyProxyTotalActivityNoticePeriodMilliseconds != nil {
		applyParameters[parameters.InproxyProxyTotalActivityNoticePeriod] = fmt.Sprintf("%dms", *config.InproxyProxyTotalActivityNoticePeriodMilliseconds)
	}

	if config.InproxyClientDialRateLimitQuantity != nil {
		applyParameters[parameters.InproxyClientDialRateLimitQuantity] = *config.InproxyClientDialRateLimitQuantity
	}

	if config.InproxyClientDialRateLimitIntervalMilliseconds != nil {
		applyParameters[parameters.InproxyClientDialRateLimitInterval] = fmt.Sprintf("%dms", *config.InproxyClientDialRateLimitIntervalMilliseconds)
	}

	if config.InproxyClientNoMatchFailoverProbability != nil {
		applyParameters[parameters.InproxyClientNoMatchFailoverProbability] = *config.InproxyClientNoMatchFailoverProbability
	}

	if config.InproxyClientNoMatchFailoverPersonalProbability != nil {
		applyParameters[parameters.InproxyClientNoMatchFailoverPersonalProbability] = *config.InproxyClientNoMatchFailoverPersonalProbability
	}

	if config.InproxyFrontingProviderClientMaxRequestTimeouts != nil {
		applyParameters[parameters.InproxyFrontingProviderClientMaxRequestTimeouts] = config.InproxyFrontingProviderClientMaxRequestTimeouts
	}

	if config.InproxyProxyOnBrokerClientFailedRetryPeriodMilliseconds != nil {
		applyParameters[parameters.InproxyProxyOnBrokerClientFailedRetryPeriod] = fmt.Sprintf("%dms", *config.InproxyProxyOnBrokerClientFailedRetryPeriodMilliseconds)
	}

	if len(config.InproxyProxyIncompatibleNetworkTypes) > 0 {
		applyParameters[parameters.InproxyProxyIncompatibleNetworkTypes] = config.InproxyProxyIncompatibleNetworkTypes
	}

	if len(config.InproxyClientIncompatibleNetworkTypes) > 0 {
		applyParameters[parameters.InproxyClientIncompatibleNetworkTypes] = config.InproxyClientIncompatibleNetworkTypes
	}

	if config.InproxyReplayRetainFailedProbability != nil {
		applyParameters[parameters.InproxyReplayRetainFailedProbability] = *config.InproxyReplayRetainFailedProbability
	}

	if config.InproxyProxyDisableWaitToShareSession != nil {
		applyParameters[parameters.InproxyProxyDisableWaitToShareSession] = *config.InproxyProxyDisableWaitToShareSession
	}

	if config.InproxyClientDisableWaitToShareSession != nil {
		applyParameters[parameters.InproxyClientDisableWaitToShareSession] = *config.InproxyClientDisableWaitToShareSession
	}

	if config.InproxyTunnelProtocolPreferProbability != nil {
		applyParameters[parameters.InproxyTunnelProtocolPreferProbability] = *config.InproxyTunnelProtocolPreferProbability
	}

	if config.InproxyTunnelProtocolForceSelectionCount != nil {
		applyParameters[parameters.InproxyTunnelProtocolForceSelectionCount] = *config.InproxyTunnelProtocolForceSelectionCount
	}

	if config.NetworkIDCacheTTLMilliseconds != nil {
		applyParameters[parameters.NetworkIDCacheTTL] = fmt.Sprintf("%dms", *config.NetworkIDCacheTTLMilliseconds)
	}

	if config.CompressTactics != nil {
		applyParameters[parameters.CompressTactics] = *config.CompressTactics
	}

	if config.EnableDSLFetcher != nil {
		applyParameters[parameters.EnableDSLFetcher] = *config.EnableDSLFetcher
	}

	if config.DSLPrioritizeDialNewServerEntryProbability != nil {
		applyParameters[parameters.DSLPrioritizeDialNewServerEntryProbability] = *config.DSLPrioritizeDialNewServerEntryProbability
	}

	if config.DSLPrioritizeDialExistingServerEntryProbability != nil {
		applyParameters[parameters.DSLPrioritizeDialExistingServerEntryProbability] = *config.DSLPrioritizeDialExistingServerEntryProbability
	}

	if config.DSLPrioritizeDialRetainFailedProbability != nil {
		applyParameters[parameters.DSLPrioritizeDialRetainFailedProbability] = *config.DSLPrioritizeDialRetainFailedProbability
	}

	if config.DSLPrioritizeDialPlaceholderTTLSeconds != nil {
		applyParameters[parameters.DSLPrioritizeDialPlaceholderTTL] = fmt.Sprintf("%ds", *config.DSLPrioritizeDialPlaceholderTTLSeconds)
	}

	if config.ServerEntryIteratorMaxMoveToFront != nil {
		applyParameters[parameters.ServerEntryIteratorResetProbability] = *config.ServerEntryIteratorResetProbability
	}

	if config.EnableDSLFetcher != nil {
		applyParameters[parameters.EnableDSLFetcher] = *config.EnableDSLFetcher
	}

	// When adding new config dial parameters that may override tactics, also
	// update setDialParametersHash.

	return applyParameters
}

func (config *Config) setDialParametersHash() {

	// Calculate and store a hash of the config values that may impact
	// dial parameters. This hash is used as part of the dial parameters
	// replay mechanism to detect when persisted dial parameters should
	// be discarded due to conflicting config changes.
	//
	// With a couple of minor exceptions, configuring dial parameters via the
	// config is intended for testing only, and so these parameters are expected
	// to be present in test runs only. It remains an important case to discard
	// replay dial parameters when test config parameters are varied.
	//
	// Hashing the parameter names detects some ambiguous hash cases, such as two
	// consecutive int64 parameters, one omitted and one not, that are flipped.
	// The serialization is not completely unambiguous, and the format is
	// currently limited by legacy cases (not invalidating replay dial parameters
	// for production clients is more important than invalidating for test runs).
	// We cannot hash the entire config JSON as it contains non-dial parameter
	// fields which may frequently change across runs.
	//
	// MD5 hash is used solely as a data checksum and not for any security
	// purpose.

	hash := md5.New()

	if len(config.LimitTunnelProtocols) > 0 {
		hash.Write([]byte("LimitTunnelProtocols"))
		for _, protocol := range config.LimitTunnelProtocols {
			hash.Write([]byte(protocol))
		}
	}

	if len(config.InitialLimitTunnelProtocols) > 0 && config.InitialLimitTunnelProtocolsCandidateCount > 0 {
		hash.Write([]byte("InitialLimitTunnelProtocols"))
		for _, protocol := range config.InitialLimitTunnelProtocols {
			hash.Write([]byte(protocol))
		}
		binary.Write(hash, binary.LittleEndian, int64(config.InitialLimitTunnelProtocolsCandidateCount))
	}

	if len(config.LimitTLSProfiles) > 0 {
		hash.Write([]byte("LimitTLSProfiles"))
		for _, profile := range config.LimitTLSProfiles {
			hash.Write([]byte(profile))
		}
	}

	if len(config.LimitQUICVersions) > 0 {
		hash.Write([]byte("LimitQUICVersions"))
		for _, version := range config.LimitQUICVersions {
			hash.Write([]byte(version))
		}
	}

	// Whether a custom User-Agent is specified is a binary flag: when not set,
	// the replay dial parameters value applies. When set, external
	// considerations apply.
	if _, ok := config.CustomHeaders["User-Agent"]; ok {
		hash.Write([]byte("CustomHeaders User-Agent"))
		hash.Write([]byte{1})
	}

	if config.UpstreamProxyURL != "" {
		hash.Write([]byte("UpstreamProxyURL"))
		hash.Write([]byte(config.UpstreamProxyURL))
	}

	if config.TransformHostNameProbability != nil {
		hash.Write([]byte("TransformHostNameProbability"))
		binary.Write(hash, binary.LittleEndian, *config.TransformHostNameProbability)
	}

	if config.FragmentorProbability != nil {
		hash.Write([]byte("FragmentorProbability"))
		binary.Write(hash, binary.LittleEndian, *config.FragmentorProbability)
	}

	if len(config.FragmentorLimitProtocols) > 0 {
		hash.Write([]byte("FragmentorLimitProtocols"))
		for _, protocol := range config.FragmentorLimitProtocols {
			hash.Write([]byte(protocol))
		}
	}

	if config.FragmentorMinTotalBytes != nil {
		hash.Write([]byte("FragmentorMinTotalBytes"))
		binary.Write(hash, binary.LittleEndian, int64(*config.FragmentorMinTotalBytes))
	}

	if config.FragmentorMaxTotalBytes != nil {
		hash.Write([]byte("FragmentorMaxTotalBytes"))
		binary.Write(hash, binary.LittleEndian, int64(*config.FragmentorMaxTotalBytes))
	}

	if config.FragmentorMinWriteBytes != nil {
		hash.Write([]byte("FragmentorMinWriteBytes"))
		binary.Write(hash, binary.LittleEndian, int64(*config.FragmentorMinWriteBytes))
	}

	if config.FragmentorMaxWriteBytes != nil {
		hash.Write([]byte("FragmentorMaxWriteBytes"))
		binary.Write(hash, binary.LittleEndian, int64(*config.FragmentorMaxWriteBytes))
	}

	if config.FragmentorMinDelayMicroseconds != nil {
		hash.Write([]byte("FragmentorMinDelayMicroseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.FragmentorMinDelayMicroseconds))
	}

	if config.FragmentorMaxDelayMicroseconds != nil {
		hash.Write([]byte("FragmentorMaxDelayMicroseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.FragmentorMaxDelayMicroseconds))
	}

	if config.MeekTrafficShapingProbability != nil {
		hash.Write([]byte("MeekTrafficShapingProbability"))
		binary.Write(hash, binary.LittleEndian, *config.MeekTrafficShapingProbability)
	}

	if len(config.MeekTrafficShapingLimitProtocols) > 0 {
		hash.Write([]byte("MeekTrafficShapingLimitProtocols"))
		for _, protocol := range config.MeekTrafficShapingLimitProtocols {
			hash.Write([]byte(protocol))
		}
	}

	if config.MeekMinLimitRequestPayloadLength != nil {
		hash.Write([]byte("MeekMinLimitRequestPayloadLength"))
		binary.Write(hash, binary.LittleEndian, int64(*config.MeekMinLimitRequestPayloadLength))
	}

	if config.MeekMaxLimitRequestPayloadLength != nil {
		hash.Write([]byte("MeekMaxLimitRequestPayloadLength"))
		binary.Write(hash, binary.LittleEndian, int64(*config.MeekMaxLimitRequestPayloadLength))
	}

	if config.MeekRedialTLSProbability != nil {
		hash.Write([]byte("MeekRedialTLSProbability"))
		binary.Write(hash, binary.LittleEndian, *config.MeekRedialTLSProbability)
	}

	if config.ObfuscatedSSHMinPadding != nil {
		hash.Write([]byte("ObfuscatedSSHMinPadding"))
		binary.Write(hash, binary.LittleEndian, int64(*config.ObfuscatedSSHMinPadding))
	}

	if config.ObfuscatedSSHMaxPadding != nil {
		hash.Write([]byte("ObfuscatedSSHMaxPadding"))
		binary.Write(hash, binary.LittleEndian, int64(*config.ObfuscatedSSHMaxPadding))
	}

	if config.LivenessTestMinUpstreamBytes != nil {
		hash.Write([]byte("LivenessTestMinUpstreamBytes"))
		binary.Write(hash, binary.LittleEndian, int64(*config.LivenessTestMinUpstreamBytes))
	}

	if config.LivenessTestMaxUpstreamBytes != nil {
		hash.Write([]byte("LivenessTestMaxUpstreamBytes"))
		binary.Write(hash, binary.LittleEndian, int64(*config.LivenessTestMaxUpstreamBytes))
	}

	if config.LivenessTestMinDownstreamBytes != nil {
		hash.Write([]byte("LivenessTestMinDownstreamBytes"))
		binary.Write(hash, binary.LittleEndian, int64(*config.LivenessTestMinDownstreamBytes))
	}

	if config.LivenessTestMaxDownstreamBytes != nil {
		hash.Write([]byte("LivenessTestMaxDownstreamBytes"))
		binary.Write(hash, binary.LittleEndian, int64(*config.LivenessTestMaxDownstreamBytes))
	}

	// Legacy case: these parameters are included in the hash unconditionally,
	// and so will impact almost all production clients. These parameter names
	// are not hashed since that would invalidate all replay dial parameters for
	// existing clients whose hashes predate the inclusion of parameter names.
	binary.Write(hash, binary.LittleEndian, config.NetworkLatencyMultiplierMin)
	binary.Write(hash, binary.LittleEndian, config.NetworkLatencyMultiplierMax)
	binary.Write(hash, binary.LittleEndian, config.NetworkLatencyMultiplierLambda)

	if config.UseOnlyCustomTLSProfiles != nil {
		hash.Write([]byte("UseOnlyCustomTLSProfiles"))
		binary.Write(hash, binary.LittleEndian, *config.UseOnlyCustomTLSProfiles)
	}

	if len(config.CustomTLSProfiles) > 0 {
		hash.Write([]byte("CustomTLSProfiles"))
		for _, customTLSProfile := range config.CustomTLSProfiles {
			encodedCustomTLSProofile, _ := json.Marshal(customTLSProfile)
			hash.Write(encodedCustomTLSProofile)
		}
	}

	if config.SelectRandomizedTLSProfileProbability != nil {
		hash.Write([]byte("SelectRandomizedTLSProfileProbability"))
		binary.Write(hash, binary.LittleEndian, *config.SelectRandomizedTLSProfileProbability)
	}

	if config.NoDefaultTLSSessionIDProbability != nil {
		hash.Write([]byte("NoDefaultTLSSessionIDProbability"))
		binary.Write(hash, binary.LittleEndian, *config.NoDefaultTLSSessionIDProbability)
	}

	if len(config.DisableFrontingProviderTLSProfiles) > 0 {
		hash.Write([]byte("DisableFrontingProviderTLSProfiles"))
		encodedDisableFrontingProviderTLSProfiles, _ :=
			json.Marshal(config.DisableFrontingProviderTLSProfiles)
		hash.Write(encodedDisableFrontingProviderTLSProfiles)
	}

	if len(config.CustomHostNameRegexes) > 0 {
		hash.Write([]byte("CustomHostNameRegexes"))
		for _, customHostNameRegex := range config.CustomHostNameRegexes {
			hash.Write([]byte(customHostNameRegex))
		}
	}

	if config.CustomHostNameProbability != nil {
		hash.Write([]byte("CustomHostNameProbability"))
		binary.Write(hash, binary.LittleEndian, *config.CustomHostNameProbability)
	}

	if len(config.CustomHostNameLimitProtocols) > 0 {
		hash.Write([]byte("CustomHostNameLimitProtocols"))
		for _, protocol := range config.CustomHostNameLimitProtocols {
			hash.Write([]byte(protocol))
		}
	}

	if config.ConjureCachedRegistrationTTLSeconds != nil {
		hash.Write([]byte("ConjureCachedRegistrationTTLSeconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.ConjureCachedRegistrationTTLSeconds))
	}

	if config.ConjureAPIRegistrarBidirectionalURL != "" {
		hash.Write([]byte("ConjureAPIRegistrarBidirectionalURL"))
		hash.Write([]byte(config.ConjureAPIRegistrarBidirectionalURL))
	}

	if len(config.ConjureAPIRegistrarFrontingSpecs) > 0 {
		hash.Write([]byte("ConjureAPIRegistrarFrontingSpecs"))
		for _, frontingSpec := range config.ConjureAPIRegistrarFrontingSpecs {
			encodedFrontSpec, _ := json.Marshal(frontingSpec)
			hash.Write(encodedFrontSpec)
		}
	}

	if config.ConjureAPIRegistrarMinDelayMilliseconds != nil {
		hash.Write([]byte("ConjureAPIRegistrarMinDelayMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.ConjureAPIRegistrarMinDelayMilliseconds))
	}

	if config.ConjureAPIRegistrarMaxDelayMilliseconds != nil {
		hash.Write([]byte("ConjureAPIRegistrarMaxDelayMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.ConjureAPIRegistrarMaxDelayMilliseconds))
	}

	if config.ConjureDecoyRegistrarWidth != nil {
		hash.Write([]byte("ConjureDecoyRegistrarWidth"))
		binary.Write(hash, binary.LittleEndian, int64(*config.ConjureDecoyRegistrarWidth))
	}

	if config.ConjureDecoyRegistrarMinDelayMilliseconds != nil {
		hash.Write([]byte("ConjureDecoyRegistrarMinDelayMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.ConjureDecoyRegistrarMinDelayMilliseconds))
	}

	if config.ConjureDecoyRegistrarMaxDelayMilliseconds != nil {
		hash.Write([]byte("ConjureDecoyRegistrarMaxDelayMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.ConjureDecoyRegistrarMaxDelayMilliseconds))
	}

	if config.ConjureLimitTransports != nil {
		hash.Write([]byte("ConjureLimitTransports"))
		for _, transport := range config.ConjureLimitTransports {
			hash.Write([]byte(transport))
		}
	}

	if config.ConjureSTUNServerAddresses != nil {
		hash.Write([]byte("ConjureSTUNServerAddresses"))
		for _, address := range config.ConjureSTUNServerAddresses {
			hash.Write([]byte(address))
		}
	}

	if config.HoldOffTunnelProtocolMinDurationMilliseconds != nil {
		hash.Write([]byte("HoldOffTunnelProtocolMinDurationMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.HoldOffTunnelProtocolMinDurationMilliseconds))
	}

	if config.HoldOffTunnelProtocolMaxDurationMilliseconds != nil {
		hash.Write([]byte("HoldOffTunnelProtocolMaxDurationMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.HoldOffTunnelProtocolMaxDurationMilliseconds))
	}

	if len(config.HoldOffTunnelProtocolNames) > 0 {
		hash.Write([]byte("HoldOffTunnelProtocolNames"))
		for _, protocol := range config.HoldOffTunnelProtocolNames {
			hash.Write([]byte(protocol))
		}
	}

	if config.HoldOffTunnelProtocolProbability != nil {
		hash.Write([]byte("HoldOffTunnelProtocolProbability"))
		binary.Write(hash, binary.LittleEndian, *config.HoldOffTunnelProtocolProbability)
	}

	if config.HoldOffFrontingTunnelMinDurationMilliseconds != nil {
		hash.Write([]byte("HoldOffFrontingTunnelMinDurationMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.HoldOffFrontingTunnelMinDurationMilliseconds))
	}

	if config.HoldOffFrontingTunnelMaxDurationMilliseconds != nil {
		hash.Write([]byte("HoldOffFrontingTunnelMaxDurationMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.HoldOffFrontingTunnelMaxDurationMilliseconds))
	}

	if len(config.HoldOffFrontingTunnelProviderIDs) > 0 {
		hash.Write([]byte("HoldOffFrontingTunnelProviderIDs"))
		for _, providerID := range config.HoldOffFrontingTunnelProviderIDs {
			hash.Write([]byte(providerID))
		}
	}

	if config.HoldOffFrontingTunnelProbability != nil {
		hash.Write([]byte("HoldOffFrontingTunnelProbability"))
		binary.Write(hash, binary.LittleEndian, *config.HoldOffFrontingTunnelProbability)
	}

	if config.HoldOffDirectTunnelProbability != nil {
		hash.Write([]byte("HoldOffDirectTunnelProbability"))
		binary.Write(hash, binary.LittleEndian, *config.HoldOffDirectTunnelProbability)
	}

	if config.HoldOffDirectTunnelMinDurationMilliseconds != nil {
		hash.Write([]byte("HoldOffDirectTunnelMinDurationMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.HoldOffDirectTunnelMinDurationMilliseconds))
	}

	if config.HoldOffDirectTunnelMaxDurationMilliseconds != nil {
		hash.Write([]byte("HoldOffDirectTunnelMaxDurationMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.HoldOffDirectTunnelMaxDurationMilliseconds))
	}

	if len(config.HoldOffDirectTunnelProviderRegions) > 0 {
		hash.Write([]byte("HoldOffDirectTunnelProviderRegions"))
		for providerID, regions := range config.HoldOffDirectTunnelProviderRegions {
			hash.Write([]byte(providerID))
			for _, region := range regions {
				hash.Write([]byte(region))
			}
		}
	}

	if len(config.RestrictDirectProviderRegions) > 0 {
		hash.Write([]byte("RestrictDirectProviderRegions"))
		for providerID, regions := range config.RestrictDirectProviderRegions {
			hash.Write([]byte(providerID))
			for _, region := range regions {
				hash.Write([]byte(region))
			}
		}
	}

	if config.RestrictDirectProviderIDsClientProbability != nil {
		hash.Write([]byte("RestrictDirectProviderIDsClientProbability"))
		binary.Write(hash, binary.LittleEndian, *config.RestrictDirectProviderIDsClientProbability)
	}

	if len(config.RestrictFrontingProviderIDs) > 0 {
		hash.Write([]byte("RestrictFrontingProviderIDs"))
		for _, providerID := range config.RestrictFrontingProviderIDs {
			hash.Write([]byte(providerID))
		}
	}

	if config.RestrictFrontingProviderIDsClientProbability != nil {
		hash.Write([]byte("RestrictFrontingProviderIDsClientProbability"))
		binary.Write(hash, binary.LittleEndian, *config.RestrictFrontingProviderIDsClientProbability)
	}

	if config.HoldOffInproxyTunnelProbability != nil {
		hash.Write([]byte("HoldOffInproxyTunnelProbability"))
		binary.Write(hash, binary.LittleEndian, *config.HoldOffInproxyTunnelProbability)
	}

	if config.HoldOffInproxyTunnelMinDurationMilliseconds != nil {
		hash.Write([]byte("HoldOffInproxyTunnelMinDurationMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.HoldOffInproxyTunnelMinDurationMilliseconds))
	}

	if config.HoldOffInproxyTunnelMaxDurationMilliseconds != nil {
		hash.Write([]byte("HoldOffInproxyTunnelMaxDurationMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.HoldOffInproxyTunnelMaxDurationMilliseconds))
	}

	if len(config.HoldOffInproxyTunnelProviderRegions) > 0 {
		hash.Write([]byte("HoldOffInproxyTunnelProviderRegions"))
		for providerID, regions := range config.HoldOffInproxyTunnelProviderRegions {
			hash.Write([]byte(providerID))
			for _, region := range regions {
				hash.Write([]byte(region))
			}
		}
	}

	if len(config.RestrictInproxyProviderRegions) > 0 {
		hash.Write([]byte("RestrictInproxyProviderRegions"))
		for providerID, regions := range config.RestrictInproxyProviderRegions {
			hash.Write([]byte(providerID))
			for _, region := range regions {
				hash.Write([]byte(region))
			}
		}
	}

	if config.RestrictInproxyProviderIDsClientProbability != nil {
		hash.Write([]byte("RestrictInproxyProviderIDsClientProbability"))
		binary.Write(hash, binary.LittleEndian, *config.RestrictInproxyProviderIDsClientProbability)
	}

	if config.UpstreamProxyAllowAllServerEntrySources != nil {
		hash.Write([]byte("UpstreamProxyAllowAllServerEntrySources"))
		binary.Write(hash, binary.LittleEndian, *config.UpstreamProxyAllowAllServerEntrySources)
	}

	if len(config.LimitTunnelDialPortNumbers) > 0 {
		hash.Write([]byte("LimitTunnelDialPortNumbers"))
		encodedLimitTunnelDialPortNumbers, _ :=
			json.Marshal(config.LimitTunnelDialPortNumbers)
		hash.Write(encodedLimitTunnelDialPortNumbers)
	}

	if config.QUICDialEarlyProbability != nil {
		hash.Write([]byte("QUICDialEarlyProbability"))
		binary.Write(hash, binary.LittleEndian, *config.QUICDialEarlyProbability)
	}

	if config.QUICObfuscatedPSKProbability != nil {
		hash.Write([]byte("QUICObfuscatedPSKProbability"))
		binary.Write(hash, binary.LittleEndian, *config.QUICObfuscatedPSKProbability)
	}

	if config.QUICDisablePathMTUDiscoveryProbability != nil {
		hash.Write([]byte("QUICDisablePathMTUDiscoveryProbability"))
		binary.Write(hash, binary.LittleEndian, *config.QUICDisablePathMTUDiscoveryProbability)
	}

	if config.DNSResolverAttemptsPerServer != nil {
		hash.Write([]byte("DNSResolverAttemptsPerServer"))
		binary.Write(hash, binary.LittleEndian, int64(*config.DNSResolverAttemptsPerServer))
	}

	if config.DNSResolverRequestTimeoutMilliseconds != nil {
		hash.Write([]byte("DNSResolverRequestTimeoutMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.DNSResolverRequestTimeoutMilliseconds))
	}

	if config.DNSResolverAwaitTimeoutMilliseconds != nil {
		hash.Write([]byte("DNSResolverAwaitTimeoutMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.DNSResolverAwaitTimeoutMilliseconds))
	}

	if config.DNSResolverPreresolvedIPAddressCIDRs != nil {
		hash.Write([]byte("DNSResolverPreresolvedIPAddressCIDRs"))
		encodedDNSResolverPreresolvedIPAddressCIDRs, _ :=
			json.Marshal(config.DNSResolverPreresolvedIPAddressCIDRs)
		hash.Write(encodedDNSResolverPreresolvedIPAddressCIDRs)
	}

	if config.DNSResolverPreresolvedIPAddressProbability != nil {
		hash.Write([]byte("DNSResolverPreresolvedIPAddressProbability"))
		binary.Write(hash, binary.LittleEndian, *config.DNSResolverPreresolvedIPAddressProbability)
	}

	if config.DNSResolverAlternateServers != nil {
		hash.Write([]byte("DNSResolverAlternateServers"))
		for _, server := range config.DNSResolverAlternateServers {
			hash.Write([]byte(server))
		}
	}

	if config.DNSResolverPreferAlternateServerProbability != nil {
		hash.Write([]byte("DNSResolverPreferAlternateServerProbability"))
		binary.Write(hash, binary.LittleEndian, *config.DNSResolverPreferAlternateServerProbability)
	}

	if config.DNSResolverProtocolTransformSpecs != nil {
		hash.Write([]byte("DNSResolverProtocolTransformSpecs"))
		encodedDNSResolverProtocolTransformSpecs, _ :=
			json.Marshal(config.DNSResolverProtocolTransformSpecs)
		hash.Write(encodedDNSResolverProtocolTransformSpecs)
	}

	if config.DNSResolverProtocolTransformScopedSpecNames != nil {
		hash.Write([]byte("DNSResolverProtocolTransformScopedSpecNames"))
		encodedDNSResolverProtocolTransformScopedSpecNames, _ :=
			json.Marshal(config.DNSResolverProtocolTransformScopedSpecNames)
		hash.Write(encodedDNSResolverProtocolTransformScopedSpecNames)
	}

	if config.DNSResolverProtocolTransformProbability != nil {
		hash.Write([]byte("DNSResolverProtocolTransformProbability"))
		binary.Write(hash, binary.LittleEndian, *config.DNSResolverProtocolTransformProbability)
	}

	if config.DNSResolverQNameRandomizeCasingProbability != nil {
		hash.Write([]byte("DNSResolverQNameRandomizeCasingProbability"))
		binary.Write(hash, binary.LittleEndian, *config.DNSResolverQNameRandomizeCasingProbability)
	}

	if config.DNSResolverQNameMustMatchProbability != nil {
		hash.Write([]byte("DNSResolverQNameMustMatchProbability"))
		binary.Write(hash, binary.LittleEndian, *config.DNSResolverQNameMustMatchProbability)
	}

	if config.DNSResolverIncludeEDNS0Probability != nil {
		hash.Write([]byte("DNSResolverIncludeEDNS0Probability"))
		binary.Write(hash, binary.LittleEndian, *config.DNSResolverIncludeEDNS0Probability)
	}

	if config.DNSResolverCacheExtensionInitialTTLMilliseconds != nil {
		hash.Write([]byte("DNSResolverCacheExtensionInitialTTLMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.DNSResolverCacheExtensionInitialTTLMilliseconds))
	}

	if config.DNSResolverCacheExtensionVerifiedTTLMilliseconds != nil {
		hash.Write([]byte("DNSResolverCacheExtensionVerifiedTTLMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.DNSResolverCacheExtensionVerifiedTTLMilliseconds))
	}

	if config.DirectHTTPProtocolTransformSpecs != nil {
		hash.Write([]byte("DirectHTTPProtocolTransformSpecs"))
		encodedDirectHTTPProtocolTransformSpecs, _ :=
			json.Marshal(config.DirectHTTPProtocolTransformSpecs)
		hash.Write(encodedDirectHTTPProtocolTransformSpecs)
	}

	if config.DirectHTTPProtocolTransformScopedSpecNames != nil {
		hash.Write([]byte("DirectHTTPProtocolTransformScopedSpecNames"))
		encodedDirectHTTPProtocolTransformScopedSpecNames, _ :=
			json.Marshal(config.DirectHTTPProtocolTransformScopedSpecNames)
		hash.Write(encodedDirectHTTPProtocolTransformScopedSpecNames)
	}

	if config.DirectHTTPProtocolTransformProbability != nil {
		hash.Write([]byte("DirectHTTPProtocolTransformProbability"))
		binary.Write(hash, binary.LittleEndian, *config.DirectHTTPProtocolTransformProbability)
	}

	if config.FrontedHTTPProtocolTransformSpecs != nil {
		hash.Write([]byte("FrontedHTTPProtocolTransformSpecs"))
		encodedFrontedHTTPProtocolTransformSpecs, _ :=
			json.Marshal(config.FrontedHTTPProtocolTransformSpecs)
		hash.Write(encodedFrontedHTTPProtocolTransformSpecs)
	}

	if config.FrontedHTTPProtocolTransformScopedSpecNames != nil {
		hash.Write([]byte("FrontedHTTPProtocolTransformScopedSpecNames"))
		encodedFrontedHTTPProtocolTransformScopedSpecNames, _ :=
			json.Marshal(config.FrontedHTTPProtocolTransformScopedSpecNames)
		hash.Write(encodedFrontedHTTPProtocolTransformScopedSpecNames)
	}

	if config.FrontedHTTPProtocolTransformProbability != nil {
		hash.Write([]byte("FrontedHTTPProtocolTransformProbability"))
		binary.Write(hash, binary.LittleEndian, *config.FrontedHTTPProtocolTransformProbability)
	}

	if config.OSSHObfuscatorSeedTransformSpecs != nil {
		hash.Write([]byte("OSSHObfuscatorSeedTransformSpecs"))
		encodedOSSHObfuscatorSeedTransformSpecs, _ :=
			json.Marshal(config.OSSHObfuscatorSeedTransformSpecs)
		hash.Write(encodedOSSHObfuscatorSeedTransformSpecs)
	}

	if config.OSSHObfuscatorSeedTransformScopedSpecNames != nil {
		hash.Write([]byte("OSSHObfuscatorSeedTransformScopedSpecNames"))
		encodedOSSHObfuscatorSeedTransformScopedSpecNames, _ :=
			json.Marshal(config.OSSHObfuscatorSeedTransformScopedSpecNames)
		hash.Write(encodedOSSHObfuscatorSeedTransformScopedSpecNames)
	}

	if config.OSSHObfuscatorSeedTransformProbability != nil {
		hash.Write([]byte("OSSHObfuscatorSeedTransformProbability"))
		binary.Write(hash, binary.LittleEndian, *config.OSSHObfuscatorSeedTransformProbability)
	}

	if config.ObfuscatedQUICNonceTransformSpecs != nil {
		hash.Write([]byte("ObfuscatedQUICNonceTransformSpecs"))
		encodedObfuscatedQUICNonceTransformSpecs, _ :=
			json.Marshal(config.ObfuscatedQUICNonceTransformSpecs)
		hash.Write(encodedObfuscatedQUICNonceTransformSpecs)
	}

	if config.ObfuscatedQUICNonceTransformScopedSpecNames != nil {
		hash.Write([]byte("ObfuscatedQUICNonceTransformScopedSpecNames"))
		encodedObfuscatedQUICNonceTransformScopedSpecNames, _ :=
			json.Marshal(config.ObfuscatedQUICNonceTransformScopedSpecNames)
		hash.Write(encodedObfuscatedQUICNonceTransformScopedSpecNames)
	}

	if config.ObfuscatedQUICNonceTransformProbability != nil {
		hash.Write([]byte("ObfuscatedQUICNonceTransformProbability"))
		binary.Write(hash, binary.LittleEndian, *config.ObfuscatedQUICNonceTransformProbability)
	}

	if config.OSSHPrefixSpecs != nil {
		hash.Write([]byte("OSSHPrefixSpecs"))
		encodedOSSHPrefixSpecs, _ := json.Marshal(config.OSSHPrefixSpecs)
		hash.Write(encodedOSSHPrefixSpecs)
	}

	if config.OSSHPrefixScopedSpecNames != nil {
		hash.Write([]byte("OSSHPrefixScopedSpecNames"))
		encodedOSSHPrefixScopedSpecNames, _ := json.Marshal(config.OSSHPrefixScopedSpecNames)
		hash.Write(encodedOSSHPrefixScopedSpecNames)
	}

	if config.OSSHPrefixProbability != nil {
		hash.Write([]byte("OSSHPrefixProbability"))
		binary.Write(hash, binary.LittleEndian, *config.OSSHPrefixProbability)
	}

	if config.OSSHPrefixSplitMinDelayMilliseconds != nil {
		hash.Write([]byte("OSSHPrefixSplitMinDelayMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.OSSHPrefixSplitMinDelayMilliseconds))
	}

	if config.OSSHPrefixSplitMaxDelayMilliseconds != nil {
		hash.Write([]byte("OSSHPrefixSplitMaxDelayMilliseconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.OSSHPrefixSplitMaxDelayMilliseconds))
	}

	if config.OSSHPrefixEnableFragmentor != nil {
		hash.Write([]byte("OSSHPrefixEnableFragmentor"))
		binary.Write(hash, binary.LittleEndian, *config.OSSHPrefixEnableFragmentor)
	}

	if config.ShadowsocksPrefixSpecs != nil {
		hash.Write([]byte("ShadowsocksPrefixSpecs"))
		encodedShadowsocksPrefixSpecs, _ := json.Marshal(config.ShadowsocksPrefixSpecs)
		hash.Write(encodedShadowsocksPrefixSpecs)
	}

	if config.ShadowsocksPrefixScopedSpecNames != nil {
		hash.Write([]byte("ShadowsocksPrefixScopedSpecNames"))
		encodedShadowsocksPrefixScopedSpecNames, _ := json.Marshal(config.ShadowsocksPrefixScopedSpecNames)
		hash.Write(encodedShadowsocksPrefixScopedSpecNames)
	}

	if config.ShadowsocksPrefixProbability != nil {
		hash.Write([]byte("ShadowsocksPrefixProbability"))
		binary.Write(hash, binary.LittleEndian, *config.ShadowsocksPrefixProbability)
	}

	if config.TLSTunnelObfuscatedPSKProbability != nil {
		hash.Write([]byte("TLSTunnelObfuscatedPSKProbability"))
		binary.Write(hash, binary.LittleEndian, *config.TLSTunnelObfuscatedPSKProbability)
	}

	if config.TLSTunnelTrafficShapingProbability != nil {
		hash.Write([]byte("TLSTunnelTrafficShapingProbability"))
		binary.Write(hash, binary.LittleEndian, *config.TLSTunnelTrafficShapingProbability)
	}

	if config.TLSTunnelMinTLSPadding != nil {
		hash.Write([]byte("TLSTunnelMinTLSPadding"))
		binary.Write(hash, binary.LittleEndian, int64(*config.TLSTunnelMinTLSPadding))
	}

	if config.TLSTunnelMaxTLSPadding != nil {
		hash.Write([]byte("TLSTunnelMaxTLSPadding"))
		binary.Write(hash, binary.LittleEndian, int64(*config.TLSTunnelMaxTLSPadding))
	}

	if config.TLSFragmentClientHelloProbability != nil {
		hash.Write([]byte("TLSFragmentClientHelloProbability"))
		binary.Write(hash, binary.LittleEndian, *config.TLSFragmentClientHelloProbability)
	}

	if len(config.TLSFragmentClientHelloLimitProtocols) > 0 {
		hash.Write([]byte("TLSFragmentClientHelloLimitProtocols"))
		for _, protocol := range config.TLSFragmentClientHelloLimitProtocols {
			hash.Write([]byte(protocol))
		}
	}

	// Steering IPs are ephemeral and not replayed, so steering IP parameters
	// are excluded here.

	if config.InproxyTunnelProtocolSelectionProbability != nil {
		hash.Write([]byte("InproxyTunnelProtocolSelectionProbability"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyTunnelProtocolSelectionProbability)
	}
	if len(config.InproxyBrokerSpecs) > 0 {
		hash.Write([]byte("InproxyBrokerSpecs"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyBrokerSpecs)))
	}
	if len(config.InproxyPersonalPairingBrokerSpecs) > 0 {
		hash.Write([]byte("InproxyPersonalPairingBrokerSpecs"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyPersonalPairingBrokerSpecs)))
	}
	if len(config.InproxyProxyBrokerSpecs) > 0 {
		hash.Write([]byte("InproxyProxyBrokerSpecs"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyProxyBrokerSpecs)))
	}
	if len(config.InproxyProxyPersonalPairingBrokerSpecs) > 0 {
		hash.Write([]byte("InproxyProxyPersonalPairingBrokerSpecs"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyProxyPersonalPairingBrokerSpecs)))
	}
	if len(config.InproxyClientBrokerSpecs) > 0 {
		hash.Write([]byte("InproxyClientBrokerSpecs"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyClientBrokerSpecs)))
	}
	if len(config.InproxyClientPersonalPairingBrokerSpecs) > 0 {
		hash.Write([]byte("InproxyClientPersonalPairingBrokerSpecs"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyClientPersonalPairingBrokerSpecs)))
	}
	if config.InproxyReplayBrokerDialParametersTTLSeconds != nil {
		hash.Write([]byte("InproxyReplayBrokerDialParametersTTLSeconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.InproxyReplayBrokerDialParametersTTLSeconds))
	}
	if config.InproxyReplayBrokerUpdateFrequencySeconds != nil {
		hash.Write([]byte("InproxyReplayBrokerUpdateFrequencySeconds"))
		binary.Write(hash, binary.LittleEndian, int64(*config.InproxyReplayBrokerUpdateFrequencySeconds))
	}
	if config.InproxyReplayBrokerDialParametersProbability != nil {
		hash.Write([]byte("InproxyReplayBrokerDialParametersProbability"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyReplayBrokerDialParametersProbability)
	}
	if config.InproxyReplayBrokerRetainFailedProbability != nil {
		hash.Write([]byte("InproxyReplayBrokerRetainFailedProbability"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyReplayBrokerRetainFailedProbability)
	}
	if len(config.InproxyCommonCompartmentIDs) > 0 {
		hash.Write([]byte("InproxyCommonCompartmentIDs"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyCommonCompartmentIDs)))
	}
	if config.InproxyMaxCompartmentIDListLength != nil {
		hash.Write([]byte("InproxyMaxCompartmentIDListLength"))
		binary.Write(hash, binary.LittleEndian, int64(*config.InproxyMaxCompartmentIDListLength))
	}
	if config.InproxyDTLSRandomizationProbability != nil {
		hash.Write([]byte("InproxyDTLSRandomizationProbability"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyDTLSRandomizationProbability)
	}
	if config.InproxyWebRTCMediaStreamsProbability != nil {
		hash.Write([]byte("InproxyWebRTCMediaStreamsProbability"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyWebRTCMediaStreamsProbability)
	}
	if config.InproxyWebRTCDataChannelTrafficShapingProbability != nil {
		hash.Write([]byte("InproxyWebRTCDataChannelTrafficShapingProbability"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyWebRTCDataChannelTrafficShapingProbability)
	}
	if config.InproxyWebRTCDataChannelTrafficShapingParameters != nil {
		hash.Write([]byte("InproxyWebRTCDataChannelTrafficShapingParameters"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyWebRTCDataChannelTrafficShapingParameters)))
	}
	if config.InproxyWebRTCMediaStreamsTrafficShapingProbability != nil {
		hash.Write([]byte("InproxyWebRTCMediaStreamsTrafficShapingProbability"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyWebRTCMediaStreamsTrafficShapingProbability)
	}
	if config.InproxyWebRTCMediaStreamsTrafficShapingParameters != nil {
		hash.Write([]byte("InproxyWebRTCMediaStreamsTrafficShapingParameters"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyWebRTCMediaStreamsTrafficShapingParameters)))
	}
	if config.InproxySTUNServerAddresses != nil {
		hash.Write([]byte("InproxySTUNServerAddresses"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyProxySTUNServerAddresses)))
	}
	if config.InproxySTUNServerAddressesRFC5780 != nil {
		hash.Write([]byte("InproxySTUNServerAddressesRFC5780"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyProxySTUNServerAddressesRFC5780)))
	}
	if config.InproxyProxySTUNServerAddresses != nil {
		hash.Write([]byte("InproxyProxySTUNServerAddresses"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyProxySTUNServerAddresses)))
	}
	if config.InproxyProxySTUNServerAddressesRFC5780 != nil {
		hash.Write([]byte("InproxyProxySTUNServerAddressesRFC5780"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyProxySTUNServerAddressesRFC5780)))
	}
	if config.InproxyClientSTUNServerAddresses != nil {
		hash.Write([]byte("InproxyClientSTUNServerAddresses"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyClientSTUNServerAddresses)))
	}
	if config.InproxyClientSTUNServerAddressesRFC5780 != nil {
		hash.Write([]byte("InproxyClientSTUNServerAddressesRFC5780"))
		hash.Write([]byte(fmt.Sprintf("%+v", config.InproxyClientSTUNServerAddressesRFC5780)))
	}
	if config.InproxyClientDiscoverNATProbability != nil {
		hash.Write([]byte("InproxyClientDiscoverNATProbability"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyClientDiscoverNATProbability)
	}
	if config.InproxyDisableSTUN != nil {
		hash.Write([]byte("InproxyDisableSTUN"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyDisableSTUN)
	}
	if config.InproxyDisablePortMapping != nil {
		hash.Write([]byte("InproxyDisablePortMapping"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyDisablePortMapping)
	}
	if config.InproxyDisableInboundForMobileNetworks != nil {
		hash.Write([]byte("InproxyDisableInboundForMobileNetworks"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyDisableInboundForMobileNetworks)
	}
	if config.InproxyDisableIPv6ICECandidates != nil {
		hash.Write([]byte("InproxyDisableIPv6ICECandidates"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyDisableIPv6ICECandidates)
	}
	if config.InproxyProxyDisableSTUN != nil {
		hash.Write([]byte("InproxyProxyDisableSTUN"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyProxyDisableSTUN)
	}
	if config.InproxyProxyDisablePortMapping != nil {
		hash.Write([]byte("InproxyProxyDisablePortMapping"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyProxyDisablePortMapping)
	}
	if config.InproxyProxyDisableInboundForMobileNetworks != nil {
		hash.Write([]byte("InproxyProxyDisableInboundForMobileNetworks"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyProxyDisableInboundForMobileNetworks)
	}
	if config.InproxyProxyDisableIPv6ICECandidates != nil {
		hash.Write([]byte("InproxyProxyDisableIPv6ICECandidates"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyProxyDisableIPv6ICECandidates)
	}
	if config.InproxyClientDisableSTUN != nil {
		hash.Write([]byte("InproxyClientDisableSTUN"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyClientDisableSTUN)
	}
	if config.InproxyClientDisablePortMapping != nil {
		hash.Write([]byte("InproxyClientDisablePortMapping"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyClientDisablePortMapping)
	}
	if config.InproxyClientDisableInboundForMobileNetworks != nil {
		hash.Write([]byte("InproxyClientDisableInboundForMobileNetworks"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyClientDisableInboundForMobileNetworks)
	}
	if config.InproxyClientDisableIPv6ICECandidates != nil {
		hash.Write([]byte("InproxyClientDisableIPv6ICECandidates"))
		binary.Write(hash, binary.LittleEndian, *config.InproxyClientDisableIPv6ICECandidates)
	}

	config.dialParametersHash = hash.Sum(nil)
}

// applyAdditionalParameters decodes and applies any additional parameters
// stored in config.AdditionalParameter to the Config and returns an array
// of notices which should be logged at the info level. If there is no error,
// then config.AdditionalParameter is set to "" to conserve memory and further
// calls will do nothing. This function should only be called once.
//
// If there is an error, the existing Config is left entirely unmodified.
func (config *Config) applyAdditionalParameters() ([]string, error) {

	if config.AdditionalParameters == "" {
		return nil, nil
	}

	b, err := base64.StdEncoding.DecodeString(config.AdditionalParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if len(b) < 32 {
		return nil, errors.Tracef("invalid length, len(b) == %d", len(b))
	}

	var key [32]byte
	copy(key[:], b[:32])

	decrypted, ok := secretbox.Open(nil, b[32:], &[24]byte{}, &key)
	if !ok {
		return nil, errors.TraceNew("secretbox.Open failed")
	}

	var additionalParameters Config
	err = json.Unmarshal(decrypted, &additionalParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}

	src := reflect.ValueOf(&additionalParameters).Elem()
	dest := reflect.ValueOf(config).Elem()

	var infoNotices []string

	for i := 0; i < src.NumField(); i++ {
		if !src.Field(i).IsZero() {
			dest.Field(i).Set(src.Field(i))
			infoNotice := fmt.Sprintf("%s overridden by AdditionalParameters", dest.Type().Field(i).Name)
			infoNotices = append(infoNotices, infoNotice)
		}
	}

	// Reset field to conserve memory since this is a one-time operation.
	config.AdditionalParameters = ""

	return infoNotices, nil
}

func promoteLegacyTransferURL(URL string) parameters.TransferURLs {
	transferURLs := make(parameters.TransferURLs, 1)
	transferURLs[0] = &parameters.TransferURL{
		URL:               base64.StdEncoding.EncodeToString([]byte(URL)),
		SkipVerify:        false,
		OnlyAfterAttempts: 0,
	}
	return transferURLs
}

type loggingDeviceBinder struct {
	d DeviceBinder
}

func newLoggingDeviceBinder(d DeviceBinder) *loggingDeviceBinder {
	return &loggingDeviceBinder{d: d}
}

func (d *loggingDeviceBinder) BindToDevice(fileDescriptor int) (string, error) {
	deviceInfo, err := d.d.BindToDevice(fileDescriptor)
	if err == nil && deviceInfo != "" {
		NoticeBindToDevice(deviceInfo)
	}
	return deviceInfo, err
}

const unknownNetworkID = "UNKNOWN"

type staticNetworkIDGetter struct {
	networkID string
}

func newStaticNetworkIDGetter(networkID string) *staticNetworkIDGetter {
	return &staticNetworkIDGetter{networkID: networkID}
}

func (n *staticNetworkIDGetter) GetNetworkID() string {
	return n.networkID
}

type commonNetworkIDGetter struct {
}

func newCommonNetworkIDGetter() *commonNetworkIDGetter {
	return &commonNetworkIDGetter{}
}

func (n *commonNetworkIDGetter) GetNetworkID() string {
	networkID, err := networkid.Get()
	if err != nil {
		NoticeError("networkid.Get failed: %v", errors.Trace(err))
		return unknownNetworkID
	}
	return networkID
}

type loggingNetworkIDGetter struct {
	n NetworkIDGetter
}

func newLoggingNetworkIDGetter(n NetworkIDGetter) *loggingNetworkIDGetter {
	return &loggingNetworkIDGetter{n: n}
}

func (n *loggingNetworkIDGetter) GetNetworkID() string {
	networkID := n.n.GetNetworkID()

	// All PII must appear after the initial "-"
	// See: https://godoc.org/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon#NetworkIDGetter
	logNetworkID := networkID
	index := strings.Index(logNetworkID, "-")
	if index != -1 {
		logNetworkID = logNetworkID[:index]
	}
	if len(logNetworkID)+1 < len(networkID) {
		// Indicate when additional network info was present after the first "-".
		logNetworkID += "+[redacted]"
	}
	NoticeNetworkID(logNetworkID)

	return networkID
}

// cachingNetworkIDGetter caches the GetNetworkID result from the underlying
// network ID getter. The current GetNetworkID implementations take in the
// range of 1-7ms (Android); 2-3ms (iOS); ~3.5ms (Windows) to execute, on
// modern devices. To minimize delaying dials and other operations that start
// with fetching the current network ID, the return values are cached for a
// short time. On platforms that invoke NetworkChanged, the cache is flushed
// immediately upon a network change.
type cachingNetworkIDGetter struct {
	config *Config
	n      NetworkIDGetter

	mutex           sync.Mutex
	cachedNetworkID string
	cacheExpiry     time.Time
}

func newCachingNetworkIDGetter(
	config *Config, n NetworkIDGetter) *cachingNetworkIDGetter {

	return &cachingNetworkIDGetter{
		config: config,
		n:      n,
	}
}

func (n *cachingNetworkIDGetter) GetNetworkID() string {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.cachedNetworkID != "" && n.cacheExpiry.After(time.Now()) {
		return n.cachedNetworkID
	}

	networkID := n.n.GetNetworkID()

	p := n.config.GetParameters().Get()
	ttl := p.Duration(parameters.NetworkIDCacheTTL)

	if ttl > 0 {
		n.cachedNetworkID = networkID
		n.cacheExpiry = time.Now().Add(ttl)
	}

	return networkID
}

func (n *cachingNetworkIDGetter) FlushCache() {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.cachedNetworkID = ""
	n.cacheExpiry = time.Time{}
}

// migrationsFromLegacyNoticeFilePaths returns the file migrations which must be
// performed to move notice files from legacy file paths, which were configured
// with the legacy config fields HomepageNoticesFilename and
// RotatingNoticesFilename, to the new file paths used by Psiphon which exist
// under the data root directory.
func migrationsFromLegacyNoticeFilePaths(config *Config) []FileMigration {
	var noticeMigrations []FileMigration

	if config.MigrateHomepageNoticesFilename != "" {
		noticeMigrations = append(noticeMigrations, FileMigration{
			Name:    "hompage",
			OldPath: config.MigrateHomepageNoticesFilename,
			NewPath: config.GetHomePageFilename(),
		})
	}

	if config.MigrateRotatingNoticesFilename != "" {
		migrations := []FileMigration{
			{
				Name:    "notices",
				OldPath: config.MigrateRotatingNoticesFilename,
				NewPath: config.GetNoticesFilename(),
				IsDir:   false,
			},
			{
				Name:    "notices.1",
				OldPath: config.MigrateRotatingNoticesFilename + ".1",
				NewPath: config.GetNoticesFilename() + ".1",
			},
		}
		noticeMigrations = append(noticeMigrations, migrations...)
	}

	return noticeMigrations
}

// migrationsFromLegacyFilePaths returns the file migrations which must be
// performed to move files from legacy file paths, which were configured with
// legacy config fields, to the new file paths used by Psiphon which exist
// under the data root directory.
// Note: an attempt is made to redact any file paths from the returned error.
func migrationsFromLegacyFilePaths(config *Config) ([]FileMigration, error) {

	migrations := []FileMigration{
		{
			Name:    "psiphon.boltdb",
			OldPath: filepath.Join(config.MigrateDataStoreDirectory, "psiphon.boltdb"),
			NewPath: filepath.Join(config.GetDataStoreDirectory(), "psiphon.boltdb"),
		},
		{
			Name:    "psiphon.boltdb.lock",
			OldPath: filepath.Join(config.MigrateDataStoreDirectory, "psiphon.boltdb.lock"),
			NewPath: filepath.Join(config.GetDataStoreDirectory(), "psiphon.boltdb.lock"),
		},
	}

	if config.MigrateRemoteServerListDownloadFilename != "" {

		// Migrate remote server list files

		rslMigrations := []FileMigration{
			{
				Name:    "remote_server_list",
				OldPath: config.MigrateRemoteServerListDownloadFilename,
				NewPath: config.GetRemoteServerListDownloadFilename(),
			},
			{
				Name:    "remote_server_list.part",
				OldPath: config.MigrateRemoteServerListDownloadFilename + ".part",
				NewPath: config.GetRemoteServerListDownloadFilename() + ".part",
			},
			{
				Name:    "remote_server_list.part.etag",
				OldPath: config.MigrateRemoteServerListDownloadFilename + ".part.etag",
				NewPath: config.GetRemoteServerListDownloadFilename() + ".part.etag",
			},
		}

		migrations = append(migrations, rslMigrations...)
	}

	if config.MigrateObfuscatedServerListDownloadDirectory != "" {

		// Migrate OSL registry file and downloads

		oslFileRegex, err := regexp.Compile(`^osl-.+$`)
		if err != nil {
			return nil, errors.TraceMsg(err, "failed to compile regex for osl files")
		}

		files, err := ioutil.ReadDir(config.MigrateObfuscatedServerListDownloadDirectory)
		if err != nil {
			NoticeWarning(
				"Migration: failed to read OSL download directory with error %s",
				common.RedactFilePathsError(err, config.MigrateObfuscatedServerListDownloadDirectory))
		} else {
			for _, file := range files {
				if oslFileRegex.MatchString(file.Name()) {
					fileMigration := FileMigration{
						Name:    "osl",
						OldPath: filepath.Join(config.MigrateObfuscatedServerListDownloadDirectory, file.Name()),
						NewPath: filepath.Join(config.GetObfuscatedServerListDownloadDirectory(), file.Name()),
					}
					migrations = append(migrations, fileMigration)
				}
			}
		}
	}

	if config.MigrateUpgradeDownloadFilename != "" {

		// Migrate downloaded upgrade files

		oldUpgradeDownloadFilename := filepath.Base(config.MigrateUpgradeDownloadFilename)

		// Create regex for:
		// <old_upgrade_download_filename>
		// <old_upgrade_download_filename>.<client_version_number>
		// <old_upgrade_download_filename>.<client_version_number>.part
		// <old_upgrade_download_filename>.<client_version_number>.part.etag
		upgradeDownloadFileRegex, err := regexp.Compile(`^` + oldUpgradeDownloadFilename + `(\.\d+(\.part(\.etag)?)?)?$`)
		if err != nil {
			return nil, errors.TraceMsg(err, "failed to compile regex for upgrade files")
		}

		upgradeDownloadDir := filepath.Dir(config.MigrateUpgradeDownloadFilename)

		files, err := ioutil.ReadDir(upgradeDownloadDir)
		if err != nil {
			NoticeWarning(
				"Migration: failed to read upgrade download directory with error %s",
				common.RedactFilePathsError(err, upgradeDownloadDir))
		} else {

			for _, file := range files {

				if upgradeDownloadFileRegex.MatchString(file.Name()) {

					oldFileSuffix := strings.TrimPrefix(file.Name(), oldUpgradeDownloadFilename)

					fileMigration := FileMigration{
						Name:    "upgrade",
						OldPath: filepath.Join(upgradeDownloadDir, file.Name()),
						NewPath: config.GetUpgradeDownloadFilename() + oldFileSuffix,
					}
					migrations = append(migrations, fileMigration)
				}
			}
		}
	}

	return migrations, nil
}
