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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

const (
	TUNNEL_POOL_SIZE = 1

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
	DataRootDirectory string

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
	UseNoticeFiles *UseNoticeFiles

	// PropagationChannelId is a string identifier which indicates how the
	// Psiphon client was distributed. This parameter is required. This value
	// is supplied by and depends on the Psiphon Network, and is typically
	// embedded in the client binary.
	PropagationChannelId string

	// SponsorId is a string identifier which indicates who is sponsoring this
	// Psiphon client. One purpose of this value is to determine the home
	// pages for display. This parameter is required. This value is supplied
	// by and depends on the Psiphon Network, and is typically embedded in the
	// client binary.
	SponsorId string

	// ClientVersion is the client version number that the client reports to
	// the server. The version number refers to the host client application,
	// not the core tunnel library. One purpose of this value is to enable
	// automatic updates. This value is supplied by and depends on the Psiphon
	// Network, and is typically embedded in the client binary.
	//
	// Note that sending a ClientPlatform string which includes "windows"
	// (case insensitive) and a ClientVersion of <= 44 will cause an error in
	// processing the response to DoConnectedRequest calls.
	ClientVersion string

	// ClientPlatform is the client platform ("Windows", "Android", etc.) that
	// the client reports to the server.
	ClientPlatform string

	// TunnelWholeDevice is a flag that is passed through to the handshake
	// request for stats purposes. Set to 1 when the host application is
	// tunneling the whole device, 0 otherwise.
	TunnelWholeDevice int

	// EgressRegion is a ISO 3166-1 alpha-2 country code which indicates which
	// country to egress from. For the default, "", the best performing server
	// in any country is selected.
	EgressRegion string

	// ListenInterface specifies which interface to listen on.  If no
	// interface is provided then listen on 127.0.0.1. If 'any' is provided
	// then use 0.0.0.0. If there are multiple IP addresses on an interface
	// use the first IPv4 address.
	ListenInterface string

	// DisableLocalSocksProxy disables running the local SOCKS proxy.
	DisableLocalSocksProxy bool

	// LocalSocksProxyPort specifies a port number for the local SOCKS proxy
	// running at 127.0.0.1. For the default value, 0, the system selects a
	// free port (a notice reporting the selected port is emitted).
	LocalSocksProxyPort int

	// LocalHttpProxyPort specifies a port number for the local HTTP proxy
	// running at 127.0.0.1. For the default value, 0, the system selects a
	// free port (a notice reporting the selected port is emitted).
	LocalHttpProxyPort int

	// DisableLocalHTTPProxy disables running the local HTTP proxy.
	DisableLocalHTTPProxy bool

	// NetworkLatencyMultiplier is a multiplier that is to be applied to
	// default network event timeouts. Set this to tune performance for
	// slow networks.
	// When set, must be >= 1.0.
	NetworkLatencyMultiplier float64

	// LimitTunnelProtocols indicates which protocols to use. Valid values
	// include:
	// "SSH", "OSSH", "UNFRONTED-MEEK-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH",
	// "UNFRONTED-MEEK-SESSION-TICKET-OSSH", "FRONTED-MEEK-OSSH",
	// "FRONTED-MEEK-HTTP-OSSH", "QUIC-OSSH", "MARIONETTE-OSSH", and
	// "TAPDANCE-OSSH".
	// For the default, an empty list, all protocols are used.
	LimitTunnelProtocols []string

	// InitialLimitTunnelProtocols is an optional initial phase of limited
	// protocols for the first InitialLimitTunnelProtocolsCandidateCount
	// candidates; after these candidates, LimitTunnelProtocols applies.
	//
	// For the default, an empty list, InitialLimitTunnelProtocols is off.
	InitialLimitTunnelProtocols []string

	// InitialLimitTunnelProtocolsCandidateCount is the number of candidates
	// to which InitialLimitTunnelProtocols is applied instead of
	// LimitTunnelProtocols.
	//
	// For the default, 0, InitialLimitTunnelProtocols is off.
	InitialLimitTunnelProtocolsCandidateCount int

	// LimitTLSProfiles indicates which TLS profiles to select from. Valid
	// values are listed in protocols.SupportedTLSProfiles.
	// For the default, an empty list, all profiles are candidates for
	// selection.
	LimitTLSProfiles []string

	// LimitQUICVersions indicates which QUIC versions to select from. Valid
	// values are listed in protocols.SupportedQUICVersions.
	// For the default, an empty list, all versions are candidates for
	// selection.
	LimitQUICVersions []string

	// EstablishTunnelTimeoutSeconds specifies a time limit after which to
	// halt the core tunnel controller if no tunnel has been established. The
	// default is parameters.EstablishTunnelTimeout.
	EstablishTunnelTimeoutSeconds *int

	// EstablishTunnelPausePeriodSeconds specifies the delay between attempts
	// to establish tunnels. Briefly pausing allows for network conditions to
	// improve and for asynchronous operations such as fetch remote server
	// list to complete. If omitted, a default value is used. This value is
	// typical overridden for testing.
	EstablishTunnelPausePeriodSeconds *int

	// EstablishTunnelPausePeriodSeconds specifies the grace period, or head
	// start, provided to the affinity server candidate when establishing. The
	// affinity server is the server used for the last established tunnel.
	EstablishTunnelServerAffinityGracePeriodMilliseconds *int

	// ConnectionWorkerPoolSize specifies how many connection attempts to
	// attempt in parallel. If omitted of when 0, a default is used; this is
	// recommended.
	ConnectionWorkerPoolSize int

	// TunnelPoolSize specifies how many tunnels to run in parallel. Port
	// forwards are multiplexed over multiple tunnels. If omitted or when 0,
	// the default is TUNNEL_POOL_SIZE, which is recommended.
	TunnelPoolSize int

	// StaggerConnectionWorkersMilliseconds adds a specified delay before
	// making each server candidate available to connection workers. This
	// option is enabled when StaggerConnectionWorkersMilliseconds > 0.
	StaggerConnectionWorkersMilliseconds int

	// LimitIntensiveConnectionWorkers limits the number of concurrent
	// connection workers attempting connections with resource intensive
	// protocols. This option is enabled when LimitIntensiveConnectionWorkers
	// > 0.
	LimitIntensiveConnectionWorkers int

	// LimitMeekBufferSizes selects smaller buffers for meek protocols.
	LimitMeekBufferSizes bool

	// IgnoreHandshakeStatsRegexps skips compiling and using stats regexes.
	IgnoreHandshakeStatsRegexps bool

	// UpstreamProxyURL is a URL specifying an upstream proxy to use for all
	// outbound connections. The URL should include proxy type and
	// authentication information, as required. See example URLs here:
	// https://github.com/Psiphon-Labs/psiphon-tunnel-core/tree/master/psiphon/upstreamproxy
	UpstreamProxyURL string

	// CustomHeaders is a set of additional arbitrary HTTP headers that are
	// added to all plaintext HTTP requests and requests made through an HTTP
	// upstream proxy when specified by UpstreamProxyURL.
	CustomHeaders http.Header

	// NetworkConnectivityChecker is an interface that enables tunnel-core to
	// call into the host application to check for network connectivity. See:
	// NetworkConnectivityChecker doc.
	//
	// This parameter is only applicable to library deployments.
	NetworkConnectivityChecker NetworkConnectivityChecker

	// DeviceBinder is an interface that enables tunnel-core to call into the
	// host application to bind sockets to specific devices. See: DeviceBinder
	// doc.
	//
	// This parameter is only applicable to library deployments.
	DeviceBinder DeviceBinder

	// IPv6Synthesizer is an interface that allows tunnel-core to call into
	// the host application to synthesize IPv6 addresses. See: IPv6Synthesizer
	// doc.
	//
	// This parameter is only applicable to library deployments.
	IPv6Synthesizer IPv6Synthesizer

	// DnsServerGetter is an interface that enables tunnel-core to call into
	// the host application to discover the native network DNS server
	// settings. See: DnsServerGetter doc.
	//
	// This parameter is only applicable to library deployments.
	DnsServerGetter DnsServerGetter

	// NetworkIDGetter in an interface that enables tunnel-core to call into
	// the host application to get an identifier for the host's current active
	// network. See: NetworkIDGetter doc.
	//
	// This parameter is only applicable to library deployments.
	NetworkIDGetter NetworkIDGetter

	// NetworkID, when not blank, is used as the identifier for the host's
	// current active network.
	// NetworkID is ignored when NetworkIDGetter is set.
	NetworkID string

	// DisableTactics disables tactics operations including requests, payload
	// handling, and application of parameters.
	DisableTactics bool

	// DisableReplay causes any persisted dial parameters to be ignored when
	// they would otherwise be used for replay.
	DisableReplay bool

	// TargetServerEntry is an encoded server entry. When specified, this
	// server entry is used exclusively and all other known servers are
	// ignored; also, when set, ConnectionWorkerPoolSize is ignored and
	// the pool size is 1.
	TargetServerEntry string

	// DisableApi disables Psiphon server API calls including handshake,
	// connected, status, etc. This is used for special case temporary tunnels
	// (Windows VPN mode).
	DisableApi bool

	// TargetApiProtocol specifies whether to force use of "ssh" or "web" API
	// protocol. When blank, the default, the optimal API protocol is used.
	// Note that this capability check is not applied before the
	// "CandidateServers" count is emitted.
	//
	// This parameter is intended for testing and debugging only. Not all
	// parameters are supported in the legacy "web" API protocol, including
	// speed test samples.
	TargetApiProtocol string

	// RemoteServerListURLs is list of URLs which specify locations to fetch
	// out-of-band server entries. This facility is used when a tunnel cannot
	// be established to known servers. This value is supplied by and depends
	// on the Psiphon Network, and is typically embedded in the client binary.
	// All URLs must point to the same entity with the same ETag. At least one
	// DownloadURL must have OnlyAfterAttempts = 0.
	RemoteServerListURLs parameters.DownloadURLs

	// RemoteServerListSignaturePublicKey specifies a public key that's used
	// to authenticate the remote server list payload. This value is supplied
	// by and depends on the Psiphon Network, and is typically embedded in the
	// client binary.
	RemoteServerListSignaturePublicKey string

	// DisableRemoteServerListFetcher disables fetching remote server lists.
	// This is used for special case temporary tunnels.
	DisableRemoteServerListFetcher bool

	// FetchRemoteServerListRetryPeriodMilliseconds specifies the delay before
	// resuming a remote server list download after a failure. If omitted, a
	// default value is used. This value is typical overridden for testing.
	FetchRemoteServerListRetryPeriodMilliseconds *int

	// ObfuscatedServerListRootURLs is a list of URLs which specify root
	// locations from which to fetch obfuscated server list files. This value
	// is supplied by and depends on the Psiphon Network, and is typically
	// embedded in the client binary. All URLs must point to the same entity
	// with the same ETag. At least one DownloadURL must have
	// OnlyAfterAttempts = 0.
	ObfuscatedServerListRootURLs parameters.DownloadURLs

	// SplitTunnelRoutesURLFormat is a URL which specifies the location of a
	// routes file to use for split tunnel mode. The URL must include a
	// placeholder for the client region to be supplied. Split tunnel mode
	// uses the routes file to classify port forward destinations as foreign
	// or domestic and does not tunnel domestic destinations. Split tunnel
	// mode is on when all the SplitTunnel parameters are supplied. This value
	// is supplied by and depends on the Psiphon Network, and is typically
	// embedded in the client binary.
	SplitTunnelRoutesURLFormat string

	// SplitTunnelRoutesSignaturePublicKey specifies a public key that's used
	// to authenticate the split tunnel routes payload. This value is supplied
	// by and depends on the Psiphon Network, and is typically embedded in the
	// client binary.
	SplitTunnelRoutesSignaturePublicKey string

	// SplitTunnelDNSServer specifies a DNS server to use when resolving port
	// forward target domain names to IP addresses for classification. The DNS
	// server must support TCP requests.
	SplitTunnelDNSServer string

	// UpgradeDownloadURLs is list of URLs which specify locations from which
	// to download a host client upgrade file, when one is available. The core
	// tunnel controller provides a resumable download facility which
	// downloads this resource and emits a notice when complete. This value is
	// supplied by and depends on the Psiphon Network, and is typically
	// embedded in the client binary. All URLs must point to the same entity
	// with the same ETag. At least one DownloadURL must have
	// OnlyAfterAttempts = 0.
	UpgradeDownloadURLs parameters.DownloadURLs

	// UpgradeDownloadClientVersionHeader specifies the HTTP header name for
	// the entity at UpgradeDownloadURLs which specifies the client version
	// (an integer value). A HEAD request may be made to check the version
	// number available at UpgradeDownloadURLs.
	// UpgradeDownloadClientVersionHeader is required when UpgradeDownloadURLs
	// is specified.
	UpgradeDownloadClientVersionHeader string

	// FetchUpgradeRetryPeriodMilliseconds specifies the delay before resuming
	// a client upgrade download after a failure. If omitted, a default value
	// is used. This value is typical overridden for testing.
	FetchUpgradeRetryPeriodMilliseconds *int

	// TrustedCACertificatesFilename specifies a file containing trusted CA
	// certs. When set, this toggles use of the trusted CA certs, specified in
	// TrustedCACertificatesFilename, for tunneled TLS connections that expect
	// server certificates signed with public certificate authorities
	// (currently, only upgrade downloads). This option is used with stock Go
	// TLS in cases where Go may fail to obtain a list of root CAs from the
	// operating system.
	TrustedCACertificatesFilename string

	// DisablePeriodicSshKeepAlive indicates whether to send an SSH keepalive
	// every 1-2 minutes, when the tunnel is idle. If the SSH keepalive times
	// out, the tunnel is considered to have failed.
	DisablePeriodicSshKeepAlive bool

	// DeviceRegion is the optional, reported region the host device is
	// running in. This input value should be a ISO 3166-1 alpha-2 country
	// code. The device region is reported to the server in the connected
	// request and recorded for Psiphon stats.
	//
	// When provided, this value may be used, pre-connection, to select
	// performance or circumvention optimization strategies for the given
	// region.
	DeviceRegion string

	// EmitDiagnosticNotices indicates whether to output notices containing
	// detailed information about the Psiphon session. As these notices may
	// contain sensitive information, they should not be insecurely distributed
	// or displayed to users. Default is off.
	EmitDiagnosticNotices bool

	// EmitDiagnosticNetworkParameters indicates whether to include network
	// parameters in diagnostic notices. As these parameters are sensitive
	// circumvention network information, they should not be insecurely
	// distributed or displayed to users. Default is off.
	EmitDiagnosticNetworkParameters bool

	// EmitBytesTransferred indicates whether to emit periodic notices showing
	// bytes sent and received.
	EmitBytesTransferred bool

	// EmitSLOKs indicates whether to emit notices for each seeded SLOK. As
	// this could reveal user browsing activity, it's intended for debugging
	// and testing only.
	EmitSLOKs bool

	// EmitTapdanceLogs indicates whether to emit gotapdance log messages
	// to stdout. Note that gotapdance log messages do not conform to the
	// Notice format standard. Default is off.
	EmitTapdanceLogs bool

	// EmitServerAlerts indicates whether to emit notices for server alerts.
	EmitServerAlerts bool

	// RateLimits specify throttling configuration for the tunnel.
	RateLimits common.RateLimits

	// PacketTunnelTunDeviceFileDescriptor specifies a tun device file
	// descriptor to use for running a packet tunnel. When this value is > 0,
	// a packet tunnel is established through the server and packets are
	// relayed via the tun device file descriptor. The file descriptor is
	// duped in NewController. When PacketTunnelTunDeviceFileDescriptor is
	// set, TunnelPoolSize must be 1.
	PacketTunnelTunFileDescriptor int

	// SessionID specifies a client session ID to use in the Psiphon API. The
	// session ID should be a randomly generated value that is used only for a
	// single session, which is defined as the period between a user starting
	// a Psiphon client and stopping the client.
	//
	// A session ID must be 32 hex digits (lower case). When blank, a random
	// session ID is automatically generated. Supply a session ID when a
	// single client session will cross multiple Controller instances.
	SessionID string

	// Authorizations is a list of encoded, signed access control
	// authorizations that the client has obtained and will present to the
	// server.
	Authorizations []string

	// ServerEntrySignaturePublicKey is a base64-encoded, ed25519 public
	// key value used to verify individual server entry signatures. This value
	// is supplied by and depends on the Psiphon Network, and is typically
	// embedded in the client binary.
	ServerEntrySignaturePublicKey string

	// ExchangeObfuscationKey is a base64-encoded, NaCl secretbox key used to
	// obfuscate server info exchanges between clients.
	// Required for the exchange functionality.
	ExchangeObfuscationKey string

	// TransformHostNameProbability is for testing purposes.
	TransformHostNameProbability *float64

	// FragmentorProbability and associated Fragmentor fields are for testing
	// purposes.
	FragmentorProbability          *float64
	FragmentorLimitProtocols       []string
	FragmentorMinTotalBytes        *int
	FragmentorMaxTotalBytes        *int
	FragmentorMinWriteBytes        *int
	FragmentorMaxWriteBytes        *int
	FragmentorMinDelayMicroseconds *int
	FragmentorMaxDelayMicroseconds *int

	// MeekTrafficShapingProbability and associated fields are for testing
	// purposes.
	MeekTrafficShapingProbability    *float64
	MeekTrafficShapingLimitProtocols []string
	MeekMinTLSPadding                *int
	MeekMaxTLSPadding                *int
	MeekMinLimitRequestPayloadLength *int
	MeekMaxLimitRequestPayloadLength *int
	MeekRedialTLSProbability         *float64

	// ObfuscatedSSHAlgorithms and associated ObfuscatedSSH fields are for
	// testing purposes. If specified, ObfuscatedSSHAlgorithms must have 4 SSH
	// KEX elements in order: the kex algorithm, cipher, MAC, and server host
	// key algorithm.
	ObfuscatedSSHAlgorithms []string
	ObfuscatedSSHMinPadding *int
	ObfuscatedSSHMaxPadding *int

	// LivenessTestMinUpstreamBytes and other LivenessTest fields are for
	// testing purposes.
	LivenessTestMinUpstreamBytes   *int
	LivenessTestMaxUpstreamBytes   *int
	LivenessTestMinDownstreamBytes *int
	LivenessTestMaxDownstreamBytes *int

	// ReplayCandidateCount and other Replay fields are for testing purposes.
	ReplayCandidateCount                   *int
	ReplayDialParametersTTLSeconds         *int
	ReplayTargetUpstreamBytes              *int
	ReplayTargetDownstreamBytes            *int
	ReplayTargetTunnelDurationSeconds      *int
	ReplayLaterRoundMoveToFrontProbability *float64
	ReplayRetainFailedProbability          *float64

	// NetworkLatencyMultiplierMin and other NetworkLatencyMultiplier fields are
	// for testing purposes.
	NetworkLatencyMultiplierMin    float64
	NetworkLatencyMultiplierMax    float64
	NetworkLatencyMultiplierLambda float64

	// UseOnlyCustomTLSProfiles and other TLS configuration fields are for
	// testing purposes.
	UseOnlyCustomTLSProfiles              *bool
	CustomTLSProfiles                     protocol.CustomTLSProfiles
	SelectRandomizedTLSProfileProbability *float64
	NoDefaultTLSSessionIDProbability      *float64

	// ApplicationParameters is for testing purposes.
	ApplicationParameters parameters.KeyValues

	// MigrateHompageNoticesFilename migrates a homepage file from the path
	// previously configured with setNoticeFiles to the new path for homepage
	// files under the data root directory. The file specified by this config
	// value will be moved to config.GetHomePageFilename().
	//
	// Note: see comment for config.Commit() for a description of how file
	// migrations are performed.
	//
	// If not set, no migration operation will be performed.
	MigrateHompageNoticesFilename string

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
	MigrateRotatingNoticesFilename string

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
	DataStoreDirectory string

	// MigrateDataStoreDirectory indicates the location of the datastore
	// directory, as previously configured with the deprecated
	// DataStoreDirectory config field. Datastore files found in the specified
	// directory will be moved under the data root directory.
	//
	// Note: see comment for config.Commit() for a description of how file
	// migrations are performed.
	MigrateDataStoreDirectory string

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
	RemoteServerListDownloadFilename string

	// MigrateRemoteServerListDownloadFilename indicates the location of
	// remote server list download files. The remote server list files found at
	// the specified path will be moved under the data root directory.
	//
	// Note: see comment for config.Commit() for a description of how file
	// migrations are performed.
	MigrateRemoteServerListDownloadFilename string

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
	ObfuscatedServerListDownloadDirectory string

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
	MigrateObfuscatedServerListDownloadDirectory string

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
	UpgradeDownloadFilename string

	// MigrateUpgradeDownloadFilename indicates the location of downloaded
	// application upgrade files. Downloaded upgrade files found at the
	// specified path will be moved under the data root directory.
	//
	// Note: see comment for config.Commit() for a description of how file
	// migrations are performed.
	MigrateUpgradeDownloadFilename string

	// TunnelProtocol indicates which protocol to use. For the default, "",
	// all protocols are used.
	//
	// Deprecated: Use LimitTunnelProtocols. When LimitTunnelProtocols is not
	// nil, this parameter is ignored.
	TunnelProtocol string

	// Deprecated: Use CustomHeaders. When CustomHeaders is not nil, this
	// parameter is ignored.
	UpstreamProxyCustomHeaders http.Header

	// RemoteServerListUrl is a URL which specifies a location to fetch out-
	// of-band server entries. This facility is used when a tunnel cannot be
	// established to known servers. This value is supplied by and depends on
	// the Psiphon Network, and is typically embedded in the client binary.
	//
	// Deprecated: Use RemoteServerListURLs. When RemoteServerListURLs is not
	// nil, this parameter is ignored.
	RemoteServerListUrl string

	// ObfuscatedServerListRootURL is a URL which specifies the root location
	// from which to fetch obfuscated server list files. This value is
	// supplied by and depends on the Psiphon Network, and is typically
	// embedded in the client binary.
	//
	// Deprecated: Use ObfuscatedServerListRootURLs. When
	// ObfuscatedServerListRootURLs is not nil, this parameter is ignored.
	ObfuscatedServerListRootURL string

	// UpgradeDownloadUrl specifies a URL from which to download a host client
	// upgrade file, when one is available. The core tunnel controller
	// provides a resumable download facility which downloads this resource
	// and emits a notice when complete. This value is supplied by and depends
	// on the Psiphon Network, and is typically embedded in the client binary.
	//
	// Deprecated: Use UpgradeDownloadURLs. When UpgradeDownloadURLs is not
	// nil, this parameter is ignored.
	UpgradeDownloadUrl string

	// clientParameters is the active ClientParameters with defaults, config
	// values, and, optionally, tactics applied.
	//
	// New tactics must be applied by calling Config.SetClientParameters;
	// calling clientParameters.Set directly will fail to add config values.
	clientParameters *parameters.ClientParameters

	dialParametersHash []byte

	dynamicConfigMutex sync.Mutex
	sponsorID          string
	authorizations     []string

	deviceBinder    DeviceBinder
	networkIDGetter NetworkIDGetter

	committed bool

	loadTimestamp string
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
// - In the case of directories that could have defaulted to the current working
//   directory, persistent files and directories created by Psiphon are
//   precisely targeted to avoid moving files which were not created by Psiphon.
// - If no file is found at the specified path, or an error is encountered while
//   migrating the file, then an error is logged and execution continues
//   normally.
//
// A sentinel file which signals that file migration has been completed, and
// should not be attempted again, is created under DataRootDirectory after one
// full pass through Commit(), regardless of whether file migration succeeds or
// fails. It is better to not endlessly retry file migrations on each Commit()
// because file system errors are expected to be rare and persistent files will
// be re-populated over time.
func (config *Config) Commit(migrateFromLegacyFields bool) error {

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
			return errors.Trace(err)
		}
		config.DataRootDirectory = wd
	}

	// Create root directory
	dataDirectoryPath := config.GetPsiphonDataDirectory()
	if !common.FileExists(dataDirectoryPath) {
		err := os.Mkdir(dataDirectoryPath, os.ModePerm)
		if err != nil {
			return errors.Tracef("failed to create datastore directory %s with error: %s", dataDirectoryPath, err.Error())
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

			for _, migration := range noticeMigrations {
				err := common.DoFileMigration(migration)
				if err != nil {
					alertMsg := fmt.Sprintf("Config migration: %s", errors.Trace(err))
					noticeMigrationAlertMsgs = append(noticeMigrationAlertMsgs, alertMsg)
				} else {
					infoMsg := fmt.Sprintf("Config migration: moved %s to %s", migration.OldPath, migration.NewPath)
					noticeMigrationInfoMsgs = append(noticeMigrationInfoMsgs, infoMsg)
				}
			}
		} else {
			noticeMigrationInfoMsgs = append(noticeMigrationInfoMsgs, "Config migration: migration already completed")
		}
	}

	if config.UseNoticeFiles != nil {
		setNoticeFiles(
			homepageFilePath,
			noticesFilePath,
			config.UseNoticeFiles.RotatingFileSize,
			config.UseNoticeFiles.RotatingSyncFrequency)
	}

	// Emit notices now that notice files are set if configured
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
		config.RemoteServerListURLs = promoteLegacyDownloadURL(config.RemoteServerListUrl)
	}

	if config.ObfuscatedServerListRootURL != "" && config.ObfuscatedServerListRootURLs == nil {
		config.ObfuscatedServerListRootURLs = promoteLegacyDownloadURL(config.ObfuscatedServerListRootURL)
	}

	if config.UpgradeDownloadUrl != "" && config.UpgradeDownloadURLs == nil {
		config.UpgradeDownloadURLs = promoteLegacyDownloadURL(config.UpgradeDownloadUrl)
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
			return errors.Tracef("failed to create datastore directory %s with error: %s", dataStoreDirectoryPath, err.Error())
		}
	}

	// Create OSL directory.
	oslDirectoryPath := config.GetObfuscatedServerListDownloadDirectory()
	if !common.FileExists(oslDirectoryPath) {
		err := os.Mkdir(oslDirectoryPath, os.ModePerm)
		if err != nil {
			return errors.Tracef("failed to create osl directory %s with error: %s", oslDirectoryPath, err.Error())
		}
	}

	// Create tapdance directory
	tapdanceDirectoryPath := config.GetTapdanceDirectory()
	if !common.FileExists(tapdanceDirectoryPath) {
		err := os.Mkdir(tapdanceDirectoryPath, os.ModePerm)
		if err != nil {
			return errors.Tracef("failed to create tapdance directory %s with error: %s", tapdanceDirectoryPath, err.Error())
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
		return errors.Tracef("DataRootDirectory does not exist: %s", config.DataRootDirectory)
	}

	if config.PropagationChannelId == "" {
		return errors.TraceNew("propagation channel ID is missing from the configuration file")
	}
	if config.SponsorId == "" {
		return errors.TraceNew("sponsor ID is missing from the configuration file")
	}

	_, err := strconv.Atoi(config.ClientVersion)
	if err != nil {
		return errors.Tracef("invalid client version: %s", err)
	}

	if !common.Contains(
		[]string{"", protocol.PSIPHON_SSH_API_PROTOCOL, protocol.PSIPHON_WEB_API_PROTOCOL},
		config.TargetApiProtocol) {

		return errors.TraceNew("invalid TargetApiProtocol")
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

	if config.SplitTunnelRoutesURLFormat != "" {
		if config.SplitTunnelRoutesSignaturePublicKey == "" {
			return errors.TraceNew("missing SplitTunnelRoutesSignaturePublicKey")
		}
		if config.SplitTunnelDNSServer == "" {
			return errors.TraceNew("missing SplitTunnelDNSServer")
		}
	}

	if config.UpgradeDownloadURLs != nil {
		if config.UpgradeDownloadClientVersionHeader == "" {
			return errors.TraceNew("missing UpgradeDownloadClientVersionHeader")
		}
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

	config.clientParameters, err = parameters.NewClientParameters(
		func(err error) {
			NoticeWarning("ClientParameters getValue failed: %s", err)
		})
	if err != nil {
		return errors.Trace(err)
	}

	if config.ObfuscatedSSHAlgorithms != nil &&
		len(config.ObfuscatedSSHAlgorithms) != 4 {
		// TODO: validate each algorithm?
		return errors.TraceNew("invalid ObfuscatedSSHAlgorithms")
	}

	// clientParameters.Set will validate the config fields applied to parameters.

	err = config.SetClientParameters("", false, nil)
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
	// New variables are set to avoid mutating input config fields.
	// Internally, code must use config.deviceBinder and
	// config.networkIDGetter and not the input/exported fields.

	if config.DeviceBinder != nil {
		config.deviceBinder = newLoggingDeviceBinder(config.DeviceBinder)
	}

	networkIDGetter := config.NetworkIDGetter

	if networkIDGetter == nil {
		// Limitation: unlike NetworkIDGetter, which calls back to platform APIs
		// this method of network identification is not dynamic and will not reflect
		// network changes that occur while running.
		if config.NetworkID != "" {
			networkIDGetter = newStaticNetworkGetter(config.NetworkID)
		} else {
			networkIDGetter = newStaticNetworkGetter("UNKNOWN")
		}
	}

	config.networkIDGetter = newLoggingNetworkIDGetter(networkIDGetter)

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
			NoticeInfo("MigrateDataStoreDirectory unset, using working directory %s", wd)
			config.MigrateDataStoreDirectory = wd
		}

		// Move files that exist at legacy file paths under the data root
		// directory.

		migrations, err := migrationsFromLegacyFilePaths(config)
		if err != nil {
			return errors.Trace(err)
		}

		// Do migrations

		for _, migration := range migrations {
			err := common.DoFileMigration(migration)
			if err != nil {
				NoticeWarning("Config migration: %s", errors.Trace(err))
			} else {
				NoticeInfo("Config migration: moved %s to %s", migration.OldPath, migration.NewPath)
			}
		}

		// Remove OSL directory if empty
		if config.MigrateObfuscatedServerListDownloadDirectory != "" {
			files, err := ioutil.ReadDir(config.MigrateObfuscatedServerListDownloadDirectory)
			if err != nil {
				NoticeWarning("Error reading OSL directory %s: %s", config.MigrateObfuscatedServerListDownloadDirectory, errors.Trace(err))
			} else if len(files) == 0 {
				err := os.Remove(config.MigrateObfuscatedServerListDownloadDirectory)
				if err != nil {
					NoticeWarning("Error deleting empty OSL directory %s: %s", config.MigrateObfuscatedServerListDownloadDirectory, errors.Trace(err))
				}
			}
		}

		f, err := os.Create(migrationCompleteFilePath)
		if err != nil {
			NoticeWarning("Config migration: failed to create %s with error %s", migrationCompleteFilePath, errors.Trace(err))
		} else {
			NoticeInfo("Config migration: completed")
			f.Close()
		}
	}

	config.committed = true

	return nil
}

// GetClientParameters returns a the current client parameters.
func (config *Config) GetClientParameters() *parameters.ClientParameters {
	return config.clientParameters
}

// SetClientParameters resets Config.clientParameters to the default values,
// applies any config file values, and then applies the input parameters (from
// tactics, etc.)
//
// Set skipOnError to false when initially applying only config values, as
// this will validate the values and should fail. Set skipOnError to true when
// applying tactics to ignore invalid or unknown parameter values from tactics.
//
// In the case of applying tactics, do not call Config.clientParameters.Set
// directly as this will not first apply config values.
//
// If there is an error, the existing Config.clientParameters are left
// entirely unmodified.
func (config *Config) SetClientParameters(tag string, skipOnError bool, applyParameters map[string]interface{}) error {

	setParameters := []map[string]interface{}{config.makeConfigParameters()}
	if applyParameters != nil {
		setParameters = append(setParameters, applyParameters)
	}

	counts, err := config.clientParameters.Set(tag, skipOnError, setParameters...)
	if err != nil {
		return errors.Trace(err)
	}

	NoticeInfo("applied %v parameters with tag '%s'", counts, tag)

	// Emit certain individual parameter values for quick reference in diagnostics.
	p := config.clientParameters.Get()
	NoticeInfo(
		"NetworkLatencyMultiplier Min/Max/Lambda: %f/%f/%f",
		p.Float(parameters.NetworkLatencyMultiplierMin),
		p.Float(parameters.NetworkLatencyMultiplierMax),
		p.Float(parameters.NetworkLatencyMultiplierLambda))

	// Application Parameters are feature flags/config info, delivered as Client
	// Parameters via tactics/etc., to be communicated to the outer application.
	// Emit these now, as notices.
	if p.WeightedCoinFlip(parameters.ApplicationParametersProbability) {
		NoticeApplicationParameters(p.KeyValues(parameters.ApplicationParameters))
	}

	return nil
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

// GetTapdanceDirectory returns the directory under which tapdance will create
// and manage files.
func (config *Config) GetTapdanceDirectory() string {
	return filepath.Join(config.GetPsiphonDataDirectory(), "tapdance")
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

	applyParameters[parameters.SplitTunnelRoutesURLFormat] = config.SplitTunnelRoutesURLFormat
	applyParameters[parameters.SplitTunnelRoutesSignaturePublicKey] = config.SplitTunnelRoutesSignaturePublicKey
	applyParameters[parameters.SplitTunnelDNSServer] = config.SplitTunnelDNSServer

	if config.UpgradeDownloadURLs != nil {
		applyParameters[parameters.UpgradeDownloadClientVersionHeader] = config.UpgradeDownloadClientVersionHeader
		applyParameters[parameters.UpgradeDownloadURLs] = config.UpgradeDownloadURLs
	}

	applyParameters[parameters.TunnelRateLimits] = config.RateLimits

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

	if config.ObfuscatedSSHMinPadding != nil {
		applyParameters[parameters.ObfuscatedSSHMinPadding] = *config.ObfuscatedSSHMinPadding
	}

	if config.ObfuscatedSSHMaxPadding != nil {
		applyParameters[parameters.ObfuscatedSSHMaxPadding] = *config.ObfuscatedSSHMaxPadding
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

	if config.UseOnlyCustomTLSProfiles != nil {
		applyParameters[parameters.UseOnlyCustomTLSProfiles] = *config.UseOnlyCustomTLSProfiles
	}

	if config.CustomTLSProfiles != nil {
		applyParameters[parameters.CustomTLSProfiles] = config.CustomTLSProfiles
	}

	if config.SelectRandomizedTLSProfileProbability != nil {
		applyParameters[parameters.SelectRandomizedTLSProfileProbability] = *config.SelectRandomizedTLSProfileProbability
	}

	if config.NoDefaultTLSSessionIDProbability != nil {
		applyParameters[parameters.NoDefaultTLSSessionIDProbability] = *config.NoDefaultTLSSessionIDProbability
	}

	if config.ApplicationParameters != nil {
		applyParameters[parameters.ApplicationParameters] = config.ApplicationParameters
	}

	return applyParameters
}

func (config *Config) setDialParametersHash() {

	// Calculate and store a hash of the config values that may impact
	// dial parameters. This hash is used as part of the dial parameters
	// replay mechanism to detect when persisted dial parameters should
	// be discarded due to conflicting config changes.
	//
	// MD5 hash is used solely as a data checksum and not for any security
	// purpose; serialization is not strictly unambiguous.

	hash := md5.New()

	if len(config.LimitTunnelProtocols) > 0 {
		for _, protocol := range config.LimitTunnelProtocols {
			hash.Write([]byte(protocol))
		}
	}

	if len(config.InitialLimitTunnelProtocols) > 0 && config.InitialLimitTunnelProtocolsCandidateCount > 0 {
		for _, protocol := range config.InitialLimitTunnelProtocols {
			hash.Write([]byte(protocol))
		}
		binary.Write(hash, binary.LittleEndian, int64(config.InitialLimitTunnelProtocolsCandidateCount))
	}

	if len(config.LimitTLSProfiles) > 0 {
		for _, profile := range config.LimitTLSProfiles {
			hash.Write([]byte(profile))
		}
	}

	if len(config.LimitQUICVersions) > 0 {
		for _, version := range config.LimitQUICVersions {
			hash.Write([]byte(version))
		}
	}

	// Whether a custom User-Agent is specified is a binary flag: when not set,
	// the replay dial parameters value applies. When set, external
	// considerations apply.
	if _, ok := config.CustomHeaders["User-Agent"]; ok {
		hash.Write([]byte{1})
	}

	if config.UpstreamProxyURL != "" {
		hash.Write([]byte(config.UpstreamProxyURL))
	}

	if config.TransformHostNameProbability != nil {
		binary.Write(hash, binary.LittleEndian, *config.TransformHostNameProbability)
	}

	if config.FragmentorProbability != nil {
		binary.Write(hash, binary.LittleEndian, *config.FragmentorProbability)
	}

	if len(config.FragmentorLimitProtocols) > 0 {
		for _, protocol := range config.FragmentorLimitProtocols {
			hash.Write([]byte(protocol))
		}
	}

	if config.FragmentorMinTotalBytes != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.FragmentorMinTotalBytes))
	}

	if config.FragmentorMaxTotalBytes != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.FragmentorMaxTotalBytes))
	}

	if config.FragmentorMinWriteBytes != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.FragmentorMinWriteBytes))
	}

	if config.FragmentorMaxWriteBytes != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.FragmentorMaxWriteBytes))
	}

	if config.FragmentorMinDelayMicroseconds != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.FragmentorMinDelayMicroseconds))
	}

	if config.FragmentorMaxDelayMicroseconds != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.FragmentorMaxDelayMicroseconds))
	}

	if config.MeekTrafficShapingProbability != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.MeekTrafficShapingProbability))
	}

	if len(config.MeekTrafficShapingLimitProtocols) > 0 {
		for _, protocol := range config.MeekTrafficShapingLimitProtocols {
			hash.Write([]byte(protocol))
		}
	}

	if config.MeekMinLimitRequestPayloadLength != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.MeekMinLimitRequestPayloadLength))
	}

	if config.MeekMaxLimitRequestPayloadLength != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.MeekMaxLimitRequestPayloadLength))
	}

	if config.MeekRedialTLSProbability != nil {
		binary.Write(hash, binary.LittleEndian, *config.MeekRedialTLSProbability)
	}

	if config.ObfuscatedSSHMinPadding != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.ObfuscatedSSHMinPadding))
	}

	if config.ObfuscatedSSHMaxPadding != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.ObfuscatedSSHMaxPadding))
	}

	if config.LivenessTestMinUpstreamBytes != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.LivenessTestMinUpstreamBytes))
	}

	if config.LivenessTestMaxUpstreamBytes != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.LivenessTestMaxUpstreamBytes))
	}

	if config.LivenessTestMinDownstreamBytes != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.LivenessTestMinDownstreamBytes))
	}

	if config.LivenessTestMaxDownstreamBytes != nil {
		binary.Write(hash, binary.LittleEndian, int64(*config.LivenessTestMaxDownstreamBytes))
	}

	binary.Write(hash, binary.LittleEndian, config.NetworkLatencyMultiplierMin)
	binary.Write(hash, binary.LittleEndian, config.NetworkLatencyMultiplierMax)
	binary.Write(hash, binary.LittleEndian, config.NetworkLatencyMultiplierLambda)

	if config.UseOnlyCustomTLSProfiles != nil {
		binary.Write(hash, binary.LittleEndian, *config.UseOnlyCustomTLSProfiles)
	}

	for _, customTLSProfile := range config.CustomTLSProfiles {
		// Assumes consistent definition for a given profile name
		hash.Write([]byte(customTLSProfile.Name))
	}

	if config.SelectRandomizedTLSProfileProbability != nil {
		binary.Write(hash, binary.LittleEndian, *config.SelectRandomizedTLSProfileProbability)
	}

	if config.NoDefaultTLSSessionIDProbability != nil {
		binary.Write(hash, binary.LittleEndian, *config.NoDefaultTLSSessionIDProbability)
	}

	config.dialParametersHash = hash.Sum(nil)
}

func promoteLegacyDownloadURL(URL string) parameters.DownloadURLs {
	downloadURLs := make(parameters.DownloadURLs, 1)
	downloadURLs[0] = &parameters.DownloadURL{
		URL:               base64.StdEncoding.EncodeToString([]byte(URL)),
		SkipVerify:        false,
		OnlyAfterAttempts: 0,
	}
	return downloadURLs
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

type staticNetworkGetter struct {
	networkID string
}

func newStaticNetworkGetter(networkID string) *staticNetworkGetter {
	return &staticNetworkGetter{networkID: networkID}
}

func (n *staticNetworkGetter) GetNetworkID() string {
	return n.networkID
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

// migrationsFromLegacyNoticeFilePaths returns the file migrations which must be
// performed to move notice files from legacy file paths, which were configured
// with the legacy config fields HomepageNoticesFilename and
// RotatingNoticesFilename, to the new file paths used by Psiphon which exist
// under the data root directory.
func migrationsFromLegacyNoticeFilePaths(config *Config) []common.FileMigration {
	var noticeMigrations []common.FileMigration

	if config.MigrateHompageNoticesFilename != "" {
		noticeMigrations = append(noticeMigrations, common.FileMigration{
			OldPath: config.MigrateHompageNoticesFilename,
			NewPath: config.GetHomePageFilename(),
		})
	}

	if config.MigrateRotatingNoticesFilename != "" {
		migrations := []common.FileMigration{
			{
				OldPath: config.MigrateRotatingNoticesFilename,
				NewPath: config.GetNoticesFilename(),
				IsDir:   false,
			},
			{
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
func migrationsFromLegacyFilePaths(config *Config) ([]common.FileMigration, error) {

	migrations := []common.FileMigration{
		{
			OldPath: filepath.Join(config.MigrateDataStoreDirectory, "psiphon.boltdb"),
			NewPath: filepath.Join(config.GetDataStoreDirectory(), "psiphon.boltdb"),
		},
		{
			OldPath: filepath.Join(config.MigrateDataStoreDirectory, "psiphon.boltdb.lock"),
			NewPath: filepath.Join(config.GetDataStoreDirectory(), "psiphon.boltdb.lock"),
		},
		{
			OldPath: filepath.Join(config.MigrateDataStoreDirectory, "tapdance"),
			NewPath: filepath.Join(config.GetTapdanceDirectory(), "tapdance"),
			IsDir:   true,
		},
	}

	if config.MigrateRemoteServerListDownloadFilename != "" {

		// Migrate remote server list files

		rslMigrations := []common.FileMigration{
			{
				OldPath: config.MigrateRemoteServerListDownloadFilename,
				NewPath: config.GetRemoteServerListDownloadFilename(),
			},
			{
				OldPath: config.MigrateRemoteServerListDownloadFilename + ".part",
				NewPath: config.GetRemoteServerListDownloadFilename() + ".part",
			},
			{
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
			NoticeWarning("Migration: failed to read directory %s with error %s", config.MigrateObfuscatedServerListDownloadDirectory, err)
		} else {
			for _, file := range files {
				if oslFileRegex.MatchString(file.Name()) {
					fileMigration := common.FileMigration{
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
			NoticeWarning("Migration: failed to read directory %s with error %s", upgradeDownloadDir, err)
		} else {

			for _, file := range files {

				if upgradeDownloadFileRegex.MatchString(file.Name()) {

					oldFileSuffix := strings.TrimPrefix(file.Name(), oldUpgradeDownloadFilename)

					fileMigration := common.FileMigration{
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
