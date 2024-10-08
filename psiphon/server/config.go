/*
 * Copyright (c) 2016, Psiphon Inc.
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

package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/accesscontrol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	"golang.org/x/crypto/nacl/box"
)

const (
	SERVER_CONFIG_FILENAME                              = "psiphond.config"
	SERVER_TRAFFIC_RULES_CONFIG_FILENAME                = "psiphond-traffic-rules.config"
	SERVER_OSL_CONFIG_FILENAME                          = "psiphond-osl.config"
	SERVER_TACTICS_CONFIG_FILENAME                      = "psiphond-tactics.config"
	SERVER_ENTRY_FILENAME                               = "server-entry.dat"
	DEFAULT_SERVER_IP_ADDRESS                           = "127.0.0.1"
	WEB_SERVER_SECRET_BYTE_LENGTH                       = 32
	DISCOVERY_VALUE_KEY_BYTE_LENGTH                     = 32
	SSH_USERNAME_SUFFIX_BYTE_LENGTH                     = 8
	SSH_PASSWORD_BYTE_LENGTH                            = 32
	SSH_RSA_HOST_KEY_BITS                               = 2048
	SSH_OBFUSCATED_KEY_BYTE_LENGTH                      = 32
	PEAK_UPSTREAM_FAILURE_RATE_MINIMUM_SAMPLE_SIZE      = 10
	PERIODIC_GARBAGE_COLLECTION                         = 120 * time.Second
	STOP_ESTABLISH_TUNNELS_ESTABLISHED_CLIENT_THRESHOLD = 20
	DEFAULT_LOG_FILE_REOPEN_RETRIES                     = 25
)

// Config specifies the configuration and behavior of a Psiphon
// server.
type Config struct {

	// LogLevel specifies the log level. Valid values are:
	// panic, fatal, error, warn, info, debug
	LogLevel string

	// LogFilename specifies the path of the file to log
	// to. When blank, logs are written to stderr.
	LogFilename string

	// LogFileReopenRetries specifies how many retries, each with a 1ms delay,
	// will be attempted after reopening a rotated log file fails. Retries
	// mitigate any race conditions between writes/reopens and file operations
	// performed by external log managers, such as logrotate.
	//
	// When omitted, DEFAULT_LOG_FILE_REOPEN_RETRIES is used.
	LogFileReopenRetries *int

	// LogFileCreateMode specifies that the Psiphon server should create a new
	// log file when one is not found, such as after rotation with logrotate
	// configured with nocreate. The value is the os.FileMode value to use when
	// creating the file.
	//
	// When omitted, the Psiphon server does not create log files.
	LogFileCreateMode *int

	// SkipPanickingLogWriter disables panicking when
	// unable to write any logs.
	SkipPanickingLogWriter bool

	// DiscoveryValueHMACKey is the network-wide secret value
	// used to determine a unique discovery strategy.
	DiscoveryValueHMACKey string

	// GeoIPDatabaseFilenames are paths of GeoIP2/GeoLite2
	// MaxMind database files. When empty, no GeoIP lookups are
	// performed. Each file is queried, in order, for the
	// logged fields: country code, city, and ISP. Multiple
	// file support accommodates the MaxMind distribution where
	// ISP data in a separate file.
	GeoIPDatabaseFilenames []string

	// PsinetDatabaseFilename is the path of the file containing
	// psinet.Database data.
	PsinetDatabaseFilename string

	// HostID identifies the server host; this value is included with all logs.
	HostID string

	// HostProvider identifies the server host provider; this value is
	// included with all logs and logged only when not blank.
	HostProvider string

	// ServerIPAddress is the public IP address of the server.
	ServerIPAddress string

	// TunnelProtocolPorts specifies which tunnel protocols to run
	// and which ports to listen on for each protocol. Valid tunnel
	// protocols include:
	// "SSH", "OSSH", "TLS-OSSH", "UNFRONTED-MEEK-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH",
	// "UNFRONTED-MEEK-SESSION-TICKET-OSSH", "FRONTED-MEEK-OSSH",
	// "FRONTED-MEEK-QUIC-OSSH", "FRONTED-MEEK-HTTP-OSSH", "QUIC-OSSH",
	// "TAPDANCE-OSSH", abd "CONJURE-OSSH".
	TunnelProtocolPorts map[string]int

	// TunnelProtocolPassthroughAddresses specifies passthrough addresses to be
	// used for tunnel protocols configured in TunnelProtocolPorts. Passthrough
	// is a probing defense which relays all network traffic between a client and
	// the passthrough target when the client fails anti-probing tests.
	//
	// TunnelProtocolPassthroughAddresses is supported for:
	// "TLS-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH",
	// "UNFRONTED-MEEK-SESSION-TICKET-OSSH", "UNFRONTED-MEEK-OSSH".
	TunnelProtocolPassthroughAddresses map[string]string

	// LegacyPassthrough indicates whether to expect legacy passthrough messages
	// from clients attempting to connect. This should be set for existing/legacy
	// passthrough servers only.
	LegacyPassthrough bool

	// EnableGQUIC indicates whether to enable legacy gQUIC QUIC-OSSH
	// versions, for backwards compatibility with all versions used by older
	// clients. Enabling gQUIC degrades the anti-probing stance of QUIC-OSSH,
	// as the legacy gQUIC stack will respond to probing packets.
	EnableGQUIC bool

	// SSHPrivateKey is the SSH host key. The same key is used for
	// all protocols, run by this server instance, which use SSH.
	SSHPrivateKey string

	// SSHServerVersion is the server version presented in the
	// identification string. The same value is used for all
	// protocols, run by this server instance, which use SSH.
	SSHServerVersion string

	// SSHUserName is the SSH user name to be presented by the
	// the tunnel-core client. The same value is used for all
	// protocols, run by this server instance, which use SSH.
	SSHUserName string

	// SSHPassword is the SSH password to be presented by the
	// the tunnel-core client. The same value is used for all
	// protocols, run by this server instance, which use SSH.
	SSHPassword string

	// SSHBeginHandshakeTimeoutMilliseconds specifies the timeout
	// for clients queueing to begin an SSH handshake. The default
	// is SSH_BEGIN_HANDSHAKE_TIMEOUT.
	SSHBeginHandshakeTimeoutMilliseconds *int

	// SSHHandshakeTimeoutMilliseconds specifies the timeout
	// before which a client must complete its handshake. The default
	// is SSH_HANDSHAKE_TIMEOUT.
	SSHHandshakeTimeoutMilliseconds *int

	// ObfuscatedSSHKey is the secret key for use in the Obfuscated
	// SSH protocol. The same secret key is used for all protocols,
	// run by this server instance, which use Obfuscated SSH.
	ObfuscatedSSHKey string

	// MeekCookieEncryptionPrivateKey is the NaCl private key used
	// to decrypt meek cookie payload sent from clients. The same
	// key is used for all meek protocols run by this server instance.
	MeekCookieEncryptionPrivateKey string

	// MeekObfuscatedKey is the secret key used for obfuscating
	// meek cookies sent from clients. The same key is used for all
	// meek protocols run by this server instance.
	//
	// NOTE: this key is also used by the TLS-OSSH protocol, which allows
	// clients with legacy unfronted meek-https server entries, that have the
	// passthrough capability, to connect with TLS-OSSH to the servers
	// corresponding to those server entries, which now support TLS-OSSH by
	// demultiplexing meek-https and TLS-OSSH over the meek-https port.
	MeekObfuscatedKey string

	// MeekProhibitedHeaders is a list of HTTP headers to check for
	// in client requests. If one of these headers is found, the
	// request fails. This is used to defend against abuse.
	MeekProhibitedHeaders []string

	// MeekRequiredHeaders is a list of HTTP header names and values that must
	// appear in requests. This is used to defend against abuse.
	MeekRequiredHeaders map[string]string

	// MeekServerCertificate specifies an optional certificate to use for meek
	// servers, in place of the default, randomly generate certificate. When
	// specified, the corresponding private key must be supplied in
	// MeekServerPrivateKey. Any specified certificate is used for all meek
	// listeners.
	MeekServerCertificate string

	// MeekServerPrivateKey is the private key corresponding to the optional
	// MeekServerCertificate parameter.
	MeekServerPrivateKey string

	// MeekProxyForwardedForHeaders is a list of HTTP headers which
	// may be added by downstream HTTP proxies or CDNs in front
	// of clients. These headers supply the original client IP
	// address, which is geolocated for stats purposes. Headers
	// include, for example, X-Forwarded-For. The header's value
	// is assumed to be a comma delimted list of IP addresses where
	// the client IP is the first IP address in the list. Meek protocols
	// look for these headers and use the client IP address from
	// the header if any one is present and the value is a valid
	// IP address; otherwise the direct connection remote address is
	// used as the client IP.
	MeekProxyForwardedForHeaders []string

	// MeekTurnAroundTimeoutMilliseconds specifies the amount of time meek will
	// wait for downstream bytes before responding to a request. The default is
	// MEEK_DEFAULT_TURN_AROUND_TIMEOUT.
	MeekTurnAroundTimeoutMilliseconds *int

	// MeekExtendedTurnAroundTimeoutMilliseconds specifies the extended amount of
	// time meek will wait for downstream bytes, as long as bytes arrive every
	// MeekTurnAroundTimeoutMilliseconds, before responding to a request. The
	// default is MEEK_DEFAULT_EXTENDED_TURN_AROUND_TIMEOUT.
	MeekExtendedTurnAroundTimeoutMilliseconds *int

	// MeekSkipExtendedTurnAroundThresholdBytes specifies when to skip the
	// extended turn around. When the number of bytes received in the client
	// request meets the threshold, optimize for upstream flows with quicker
	// round trip turn arounds.
	MeekSkipExtendedTurnAroundThresholdBytes *int

	// MeekMaxSessionStalenessMilliseconds specifies the TTL for meek sessions.
	// The default is MEEK_DEFAULT_MAX_SESSION_STALENESS.
	MeekMaxSessionStalenessMilliseconds *int

	// MeekHTTPClientIOTimeoutMilliseconds specifies meek HTTP server I/O
	// timeouts. The default is MEEK_DEFAULT_HTTP_CLIENT_IO_TIMEOUT.
	MeekHTTPClientIOTimeoutMilliseconds *int

	// MeekFrontedHTTPClientIOTimeoutMilliseconds specifies meek HTTP server
	// I/O timeouts for fronted protocols. The default is
	// MEEK_DEFAULT_FRONTED_HTTP_CLIENT_IO_TIMEOUT.
	MeekFrontedHTTPClientIOTimeoutMilliseconds *int

	// MeekCachedResponseBufferSize is the size of a private,
	// fixed-size buffer allocated for every meek client. The buffer
	// is used to cache response payload, allowing the client to retry
	// fetching when a network connection is interrupted. This retry
	// makes the OSSH tunnel within meek resilient to interruptions
	// at the HTTP TCP layer.
	// Larger buffers increase resiliency to interruption, but consume
	// more memory as buffers as never freed. The maximum size of a
	// response payload is a function of client activity, network
	// throughput and throttling.
	// A default of 64K is used when MeekCachedResponseBufferSize is 0.
	MeekCachedResponseBufferSize int

	// MeekCachedResponsePoolBufferSize is the size of a fixed-size,
	// shared buffer used to temporarily extend a private buffer when
	// MeekCachedResponseBufferSize is insufficient. Shared buffers
	// allow some clients to successfully retry longer response payloads
	// without allocating large buffers for all clients.
	// A default of 64K is used when MeekCachedResponsePoolBufferSize
	// is 0.
	MeekCachedResponsePoolBufferSize int

	// MeekCachedResponsePoolBufferCount is the number of shared
	// buffers. Shared buffers are allocated on first use and remain
	// allocated, so shared buffer count * size is roughly the memory
	// overhead of this facility.
	// A default of 2048 is used when MeekCachedResponsePoolBufferCount
	// is 0.
	MeekCachedResponsePoolBufferCount int

	// MeekCachedResponsePoolBufferClientLimit is the maximum number of of
	// shared buffers a single client may consume at once. A default of 32 is
	// used when MeekCachedResponsePoolBufferClientLimit is 0.
	MeekCachedResponsePoolBufferClientLimit int

	// UDPInterceptUdpgwServerAddress specifies the network address of
	// a udpgw server which clients may be port forwarding to. When
	// specified, these TCP port forwards are intercepted and handled
	// directly by this server, which parses the SSH channel using the
	// udpgw protocol. Handling includes udpgw transparent DNS: tunneled
	// UDP DNS packets are rerouted to the host's DNS server.
	//
	// The intercept is applied before the port forward destination is
	// validated against SSH_DISALLOWED_PORT_FORWARD_HOSTS and
	// AllowTCPPorts. So the intercept address may be any otherwise
	// prohibited destination.
	UDPInterceptUdpgwServerAddress string

	// DNSResolverIPAddress specifies the IP address of a DNS server
	// to be used when "/etc/resolv.conf" doesn't exist or fails to
	// parse. When blank, "/etc/resolv.conf" must contain a usable
	// "nameserver" entry.
	DNSResolverIPAddress string

	// LoadMonitorPeriodSeconds indicates how frequently to log server
	// load information (number of connected clients per tunnel protocol,
	// number of running goroutines, amount of memory allocated, etc.)
	// The default, 0, disables load logging.
	LoadMonitorPeriodSeconds int

	// PeakUpstreamFailureRateMinimumSampleSize specifies the minimum number
	// of samples (e.g., upstream port forward attempts) that are required
	// before taking a failure rate snapshot which may be recorded as
	// peak_dns_failure_rate/peak_tcp_port_forward_failure_rate.  The default
	// is PEAK_UPSTREAM_FAILURE_RATE_SAMPLE_SIZE.
	PeakUpstreamFailureRateMinimumSampleSize *int

	// ProcessProfileOutputDirectory is the path of a directory to which
	// process profiles will be written when signaled with SIGUSR2. The
	// files are overwritten on each invocation. When set to the default
	// value, blank, no profiles are written on SIGUSR2. Profiles include
	// the default profiles here: https://golang.org/pkg/runtime/pprof/#Profile.
	ProcessProfileOutputDirectory string

	// ProcessBlockProfileDurationSeconds specifies the sample duration for
	// "block" profiling. For the default, 0, no "block" profile is taken.
	ProcessBlockProfileDurationSeconds int

	// ProcessCPUProfileDurationSeconds specifies the sample duration for
	// CPU profiling. For the default, 0, no CPU profile is taken.
	ProcessCPUProfileDurationSeconds int

	// TrafficRulesFilename is the path of a file containing a JSON-encoded
	// TrafficRulesSet, the traffic rules to apply to Psiphon client tunnels.
	TrafficRulesFilename string

	// OSLConfigFilename is the path of a file containing a JSON-encoded
	// OSL Config, the OSL schemes to apply to Psiphon client tunnels.
	OSLConfigFilename string

	// RunPacketTunnel specifies whether to run a packet tunnel.
	RunPacketTunnel bool

	// PacketTunnelEgressInterface specifies tun.ServerConfig.EgressInterface.
	PacketTunnelEgressInterface string

	// PacketTunnelEnableDNSFlowTracking sets
	// tun.ServerConfig.EnableDNSFlowTracking.
	PacketTunnelEnableDNSFlowTracking bool

	// PacketTunnelDownstreamPacketQueueSize specifies
	// tun.ServerConfig.DownStreamPacketQueueSize.
	PacketTunnelDownstreamPacketQueueSize int

	// PacketTunnelSessionIdleExpirySeconds specifies
	// tun.ServerConfig.SessionIdleExpirySeconds.
	PacketTunnelSessionIdleExpirySeconds int

	// PacketTunnelSudoNetworkConfigCommands sets
	// tun.ServerConfig.SudoNetworkConfigCommands.
	PacketTunnelSudoNetworkConfigCommands bool

	// RunPacketManipulator specifies whether to run a packet manipulator.
	RunPacketManipulator bool

	// MaxConcurrentSSHHandshakes specifies a limit on the number of concurrent
	// SSH handshake negotiations. This is set to mitigate spikes in memory
	// allocations and CPU usage associated with SSH handshakes when many clients
	// attempt to connect concurrently. When a maximum limit is specified and
	// reached, additional clients that establish TCP or meek connections will
	// be disconnected after a short wait for the number of concurrent handshakes
	// to drop below the limit.
	// The default, 0 is no limit.
	MaxConcurrentSSHHandshakes int

	// PeriodicGarbageCollectionSeconds turns on periodic calls to
	// debug.FreeOSMemory, every specified number of seconds, to force garbage
	// collection and memory scavenging. Specify 0 to disable. The default is
	// PERIODIC_GARBAGE_COLLECTION.
	PeriodicGarbageCollectionSeconds *int

	// StopEstablishTunnelsEstablishedClientThreshold sets the established client
	// threshold for dumping profiles when SIGTSTP is signaled. When there are
	// less than or equal to the threshold number of established clients,
	// profiles are dumped to aid investigating unusual load limited states that
	// occur when few clients are connected and load should be relatively low. A
	// profile dump is attempted at most once per process lifetime, the first
	// time the threshold is met. Disabled when < 0.
	StopEstablishTunnelsEstablishedClientThreshold *int

	// AccessControlVerificationKeyRing is the access control authorization
	// verification key ring used to verify signed authorizations presented
	// by clients. Verified, active (unexpired) access control types will be
	// available for matching in the TrafficRulesFilter for the client via
	// AuthorizedAccessTypes. All other authorizations are ignored.
	AccessControlVerificationKeyRing accesscontrol.VerificationKeyRing

	// TacticsConfigFilename is the path of a file containing a JSON-encoded
	// tactics server configuration.
	TacticsConfigFilename string

	// BlocklistFilename is the path of a file containing a CSV-encoded
	// blocklist configuration. See NewBlocklist for more file format
	// documentation.
	BlocklistFilename string

	// BlocklistActive indicates whether to actively prevent blocklist hits in
	// addition to logging events.
	BlocklistActive bool

	// AllowBogons disables port forward bogon checks. This should be used only
	// for testing.
	AllowBogons bool

	// EnableSteeringIPs enables meek server steering IP support.
	EnableSteeringIPs bool

	// OwnEncodedServerEntries is a list of the server's own encoded server
	// entries, idenfified by server entry tag. These values are used in the
	// handshake API to update clients that don't yet have a signed copy of these
	// server entries.
	//
	// For purposes of compartmentalization, each server receives only its own
	// server entries here; and, besides the discovery server entries, in
	// psinet.Database, necessary for the discovery feature, no other server
	// entries are stored on a Psiphon server.
	OwnEncodedServerEntries map[string]string

	// MeekServerRunInproxyBroker indicates whether to run an in-proxy broker
	// endpoint and service under the meek server.
	MeekServerRunInproxyBroker bool

	// MeekServerInproxyBrokerOnly indicates whether to run only an in-proxy
	// broker under the meek server, and not run any meek tunnel protocol. To
	// run the meek listener, a meek server protocol and port must still be
	// specified in TunnelProtocolPorts, but no other tunnel protocol
	// parameters are required.
	MeekServerInproxyBrokerOnly bool

	// InproxyBrokerSessionPrivateKey specifies the broker's in-proxy session
	// private key and derived public key used by in-proxy clients and
	// proxies. This value is required when running an in-proxy broker.
	InproxyBrokerSessionPrivateKey string

	// InproxyBrokerObfuscationRootSecret specifies the broker's in-proxy
	// session root obfuscation secret used by in-proxy clients and proxies.
	// This value is required when running an in-proxy broker.
	InproxyBrokerObfuscationRootSecret string

	// InproxyBrokerServerEntrySignaturePublicKey specifies the public key
	// used to verify Psiphon server entry signature. This value is required
	// when running an in-proxy broker.
	InproxyBrokerServerEntrySignaturePublicKey string

	// InproxyBrokerAllowCommonASNMatching overrides the default broker
	// matching behavior which doesn't match non-personal in-proxy clients
	// and proxies from the same ASN. This parameter is for testing only.
	InproxyBrokerAllowCommonASNMatching bool

	// InproxyBrokerAllowBogonWebRTCConnections overrides the default broker
	// SDP validation behavior, which doesn't allow private network WebRTC
	// candidates. This parameter is for testing only.
	InproxyBrokerAllowBogonWebRTCConnections bool

	// InproxyServerSessionPrivateKey specifies the server's in-proxy session
	// private key and derived public key used by brokers. This value is
	// required when running in-proxy tunnel protocols.
	InproxyServerSessionPrivateKey string

	// InproxyServerObfuscationRootSecret specifies the server's in-proxy
	// session root obfuscation secret used by brokers. This value is
	// required when running in-proxy tunnel protocols.
	InproxyServerObfuscationRootSecret string

	sshBeginHandshakeTimeout                       time.Duration
	sshHandshakeTimeout                            time.Duration
	peakUpstreamFailureRateMinimumSampleSize       int
	periodicGarbageCollection                      time.Duration
	stopEstablishTunnelsEstablishedClientThreshold int
	dumpProfilesOnStopEstablishTunnelsDone         int32
	providerID                                     string
	frontingProviderID                             string
	region                                         string
	runningProtocols                               []string
}

// GetLogFileReopenConfig gets the reopen retries, and create/mode inputs for
// rotate.NewRotatableFileWriter, which is used when writing to log files.
//
// By default, we expect the log files to be managed by logrotate, with
// logrotate configured to re-create the next log file after rotation. As
// described in the documentation for rotate.NewRotatableFileWriter, and as
// observed in production, we occasionally need retries when attempting to
// reopen the log file post-rotation; and we avoid conflicts, and spurious
// re-rotations, by disabling file create in rotate.NewRotatableFileWriter. In
// large scale production, incidents requiring retry are very rare, so the
// retry delay is not expected to have a significant impact on performance.
//
// The defaults may be overriden in the Config.
func (config *Config) GetLogFileReopenConfig() (int, bool, os.FileMode) {

	retries := DEFAULT_LOG_FILE_REOPEN_RETRIES
	if config.LogFileReopenRetries != nil {
		retries = *config.LogFileReopenRetries
	}
	create := false
	mode := os.FileMode(0)
	if config.LogFileCreateMode != nil {
		create = true
		mode = os.FileMode(*config.LogFileCreateMode)
	}
	return retries, create, mode
}

// RunLoadMonitor indicates whether to monitor and log server load.
func (config *Config) RunLoadMonitor() bool {
	return config.LoadMonitorPeriodSeconds > 0
}

// RunPeriodicGarbageCollection indicates whether to run periodic garbage collection.
func (config *Config) RunPeriodicGarbageCollection() bool {
	return config.periodicGarbageCollection > 0
}

// DumpProfilesOnStopEstablishTunnels indicates whether dump profiles due to
// an unexpectedly low number of established clients during high load.
func (config *Config) DumpProfilesOnStopEstablishTunnels(establishedClientsCount int) bool {
	if config.stopEstablishTunnelsEstablishedClientThreshold < 0 {
		return false
	}
	if atomic.LoadInt32(&config.dumpProfilesOnStopEstablishTunnelsDone) != 0 {
		return false
	}
	dump := (establishedClientsCount <= config.stopEstablishTunnelsEstablishedClientThreshold)
	atomic.StoreInt32(&config.dumpProfilesOnStopEstablishTunnelsDone, 1)
	return dump
}

// GetOwnEncodedServerEntry returns one of the server's own server entries, as
// identified by the server entry tag.
func (config *Config) GetOwnEncodedServerEntry(serverEntryTag string) (string, bool) {
	serverEntry, ok := config.OwnEncodedServerEntries[serverEntryTag]
	return serverEntry, ok
}

// GetProviderID returns the provider ID associated with the server.
func (config *Config) GetProviderID() string {
	return config.providerID
}

// GetFrontingProviderID returns the fronting provider ID associated with the
// server's fronted protocol(s).
func (config *Config) GetFrontingProviderID() string {
	return config.frontingProviderID
}

// GetRegion returns the region associated with the server.
func (config *Config) GetRegion() string {
	return config.region
}

// GetRunningProtocols returns the list of protcols this server is running.
// The caller must not mutate the return value.
func (config *Config) GetRunningProtocols() []string {
	return config.runningProtocols
}

// LoadConfig loads and validates a JSON encoded server config.
func LoadConfig(configJSON []byte) (*Config, error) {

	var config Config
	err := json.Unmarshal(configJSON, &config)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if config.ServerIPAddress == "" {
		return nil, errors.TraceNew("ServerIPAddress is required")
	}

	if config.MeekServerRunInproxyBroker {
		if config.InproxyBrokerSessionPrivateKey == "" {
			return nil, errors.TraceNew("Inproxy Broker requires InproxyBrokerSessionPrivateKey")
		}
		if config.InproxyBrokerObfuscationRootSecret == "" {
			return nil, errors.TraceNew("Inproxy Broker requires InproxyBrokerObfuscationRootSecret")
		}

		// There must be at least one meek tunnel protocol configured for
		// MeekServer to run and host an in-proxy broker. Since each
		// MeekServer instance runs its own in-proxy Broker instance, allow
		// at most one meek tunnel protocol to be configured so all
		// connections to the broker use the same, unambiguous instance.
		meekServerCount := 0
		for tunnelProtocol := range config.TunnelProtocolPorts {
			if protocol.TunnelProtocolUsesMeek(tunnelProtocol) {
				meekServerCount += 1
			}
		}
		if meekServerCount != 1 {
			return nil, errors.TraceNew("Inproxy Broker requires one MeekServer instance")
		}
	}

	if config.MeekServerInproxyBrokerOnly {
		if !config.MeekServerRunInproxyBroker {
			return nil, errors.TraceNew("Inproxy Broker-only mode requires MeekServerRunInproxyBroker")
		}
	}

	for tunnelProtocol := range config.TunnelProtocolPorts {
		if !common.Contains(protocol.SupportedTunnelProtocols, tunnelProtocol) {
			return nil, errors.Tracef("Unsupported tunnel protocol: %s", tunnelProtocol)
		}

		if config.MeekServerInproxyBrokerOnly && protocol.TunnelProtocolUsesMeek(tunnelProtocol) {
			// In in-proxy broker-only mode, the TunnelProtocolPorts must be
			// specified in order to run the MeekServer, but none of the
			// following meek tunnel parameters are required.
			continue
		}

		if protocol.TunnelProtocolUsesInproxy(tunnelProtocol) && !inproxy.Enabled() {
			// Note that, technically, it may be possible to allow this case,
			// since PSIPHON_ENABLE_INPROXY is currently required only for
			// client/proxy-side WebRTC functionality, although that could change.
			return nil, errors.TraceNew("inproxy implementation is not enabled")
		}

		if protocol.TunnelProtocolUsesSSH(tunnelProtocol) ||
			protocol.TunnelProtocolUsesObfuscatedSSH(tunnelProtocol) {
			if config.SSHPrivateKey == "" || config.SSHServerVersion == "" ||
				config.SSHUserName == "" || config.SSHPassword == "" {
				return nil, errors.Tracef(
					"Tunnel protocol %s requires SSHPrivateKey, SSHServerVersion, SSHUserName, SSHPassword",
					tunnelProtocol)
			}
		}
		if protocol.TunnelProtocolUsesObfuscatedSSH(tunnelProtocol) {
			if config.ObfuscatedSSHKey == "" {
				return nil, errors.Tracef(
					"Tunnel protocol %s requires ObfuscatedSSHKey",
					tunnelProtocol)
			}
		}
		if protocol.TunnelProtocolUsesTLSOSSH(tunnelProtocol) {
			// Meek obfuscated key used for legacy reasons. See comment for
			// MeekObfuscatedKey.
			if config.MeekObfuscatedKey == "" {
				return nil, errors.Tracef(
					"Tunnel protocol %s requires MeekObfuscatedKey",
					tunnelProtocol)
			}
		}
		if protocol.TunnelProtocolUsesMeekHTTP(tunnelProtocol) ||
			protocol.TunnelProtocolUsesMeekHTTPS(tunnelProtocol) {
			if config.MeekCookieEncryptionPrivateKey == "" || config.MeekObfuscatedKey == "" {
				return nil, errors.Tracef(
					"Tunnel protocol %s requires MeekCookieEncryptionPrivateKey, MeekObfuscatedKey",
					tunnelProtocol)
			}
		}

		// For FRONTED QUIC and HTTP, HTTPS is always used on the
		// edge-to-server hop, so it must be enabled or else this
		// configuration will not work. There is no FRONTED QUIC listener at
		// all; see TunnelServer.Run.
		if protocol.TunnelProtocolUsesFrontedMeek(tunnelProtocol) {
			_, ok := config.TunnelProtocolPorts[protocol.TUNNEL_PROTOCOL_FRONTED_MEEK]
			if !ok {
				return nil, errors.Tracef(
					"Tunnel protocol %s requires %s to be enabled",
					tunnelProtocol,
					protocol.TUNNEL_PROTOCOL_FRONTED_MEEK)
			}
		}
	}

	for tunnelProtocol, address := range config.TunnelProtocolPassthroughAddresses {
		if !protocol.TunnelProtocolSupportsPassthrough(tunnelProtocol) {
			return nil, errors.Tracef("Passthrough unsupported tunnel protocol: %s", tunnelProtocol)
		}
		if _, _, err := net.SplitHostPort(address); err != nil {
			if err != nil {
				return nil, errors.Tracef(
					"Tunnel protocol %s passthrough address %s invalid: %s",
					tunnelProtocol, address, err)
			}
		}
	}

	config.sshBeginHandshakeTimeout = SSH_BEGIN_HANDSHAKE_TIMEOUT
	if config.SSHBeginHandshakeTimeoutMilliseconds != nil {
		config.sshBeginHandshakeTimeout = time.Duration(*config.SSHBeginHandshakeTimeoutMilliseconds) * time.Millisecond
	}

	config.sshHandshakeTimeout = SSH_HANDSHAKE_TIMEOUT
	if config.SSHHandshakeTimeoutMilliseconds != nil {
		config.sshHandshakeTimeout = time.Duration(*config.SSHHandshakeTimeoutMilliseconds) * time.Millisecond
	}

	if config.ObfuscatedSSHKey != "" {
		seed, err := protocol.DeriveSSHServerVersionPRNGSeed(config.ObfuscatedSSHKey)
		if err != nil {
			return nil, errors.Tracef(
				"DeriveSSHServerVersionPRNGSeed failed: %s", err)
		}

		serverVersion := values.GetSSHServerVersion(seed)
		if serverVersion != "" {
			config.SSHServerVersion = serverVersion
		}
	}

	if config.UDPInterceptUdpgwServerAddress != "" {
		if err := validateNetworkAddress(config.UDPInterceptUdpgwServerAddress, true); err != nil {
			return nil, errors.Tracef("UDPInterceptUdpgwServerAddress is invalid: %s", err)
		}
	}

	if config.DNSResolverIPAddress != "" {
		if net.ParseIP(config.DNSResolverIPAddress) == nil {
			return nil, errors.Tracef("DNSResolverIPAddress is invalid")
		}
	}

	config.peakUpstreamFailureRateMinimumSampleSize = PEAK_UPSTREAM_FAILURE_RATE_MINIMUM_SAMPLE_SIZE
	if config.PeakUpstreamFailureRateMinimumSampleSize != nil {
		config.peakUpstreamFailureRateMinimumSampleSize = *config.PeakUpstreamFailureRateMinimumSampleSize
	}

	config.periodicGarbageCollection = PERIODIC_GARBAGE_COLLECTION
	if config.PeriodicGarbageCollectionSeconds != nil {
		config.periodicGarbageCollection = time.Duration(*config.PeriodicGarbageCollectionSeconds) * time.Second
	}

	config.stopEstablishTunnelsEstablishedClientThreshold = STOP_ESTABLISH_TUNNELS_ESTABLISHED_CLIENT_THRESHOLD
	if config.StopEstablishTunnelsEstablishedClientThreshold != nil {
		config.stopEstablishTunnelsEstablishedClientThreshold = *config.StopEstablishTunnelsEstablishedClientThreshold
	}

	err = accesscontrol.ValidateVerificationKeyRing(&config.AccessControlVerificationKeyRing)
	if err != nil {
		return nil, errors.Tracef(
			"AccessControlVerificationKeyRing is invalid: %s", err)
	}

	// Limitation: the following is a shortcut which extracts the server's
	// fronting provider ID from the server's OwnEncodedServerEntries. This logic
	// assumes a server has only one fronting provider. In principle, it's
	// possible for server with multiple server entries to run multiple fronted
	// protocols, each with a different fronting provider ID.
	//
	// TODO: add an explicit parameter mapping tunnel protocol ports to fronting
	// provider IDs.

	for _, encodedServerEntry := range config.OwnEncodedServerEntries {
		serverEntry, err := protocol.DecodeServerEntry(encodedServerEntry, "", "")
		if err != nil {
			return nil, errors.Tracef(
				"protocol.DecodeServerEntry failed: %s", err)
		}
		if config.providerID == "" {
			config.providerID = serverEntry.ProviderID
		} else if config.providerID != serverEntry.ProviderID {
			return nil, errors.Tracef("unsupported multiple ProviderID values")
		}
		if config.frontingProviderID == "" {
			config.frontingProviderID = serverEntry.FrontingProviderID
		} else if config.frontingProviderID != serverEntry.FrontingProviderID {
			return nil, errors.Tracef("unsupported multiple FrontingProviderID values")
		}
		if config.region == "" {
			config.region = serverEntry.Region
		} else if config.region != serverEntry.Region {
			return nil, errors.Tracef("unsupported multiple Region values")
		}
	}

	config.runningProtocols = []string{}
	for tunnelProtocol := range config.TunnelProtocolPorts {
		config.runningProtocols = append(config.runningProtocols, tunnelProtocol)
	}

	return &config, nil
}

func validateNetworkAddress(address string, requireIPaddress bool) error {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if requireIPaddress && net.ParseIP(host) == nil {
		return errors.TraceNew("host must be an IP address")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	if port < 0 || port > 65535 {
		return errors.TraceNew("invalid port")
	}
	return nil
}

// GenerateConfigParams specifies customizations to be applied to
// a generated server config.
type GenerateConfigParams struct {
	LogFilename                        string
	SkipPanickingLogWriter             bool
	LogLevel                           string
	ServerEntrySignaturePublicKey      string
	ServerEntrySignaturePrivateKey     string
	ServerIPAddress                    string
	TunnelProtocolPorts                map[string]int
	TunnelProtocolPassthroughAddresses map[string]string
	TrafficRulesConfigFilename         string
	OSLConfigFilename                  string
	TacticsConfigFilename              string
	TacticsRequestPublicKey            string
	TacticsRequestObfuscatedKey        string
	Passthrough                        bool
	LegacyPassthrough                  bool
	LimitQUICVersions                  protocol.QUICVersions
	EnableGQUIC                        bool
	FrontingProviderID                 string
}

// GenerateConfig creates a new Psiphon server config. It returns JSON encoded
// configs and a client-compatible "server entry" for the server. It generates
// all necessary secrets and key material, which are emitted in the config
// file and server entry as necessary.
//
// GenerateConfig uses sample values for many fields. The intention is for
// generated configs to be used for testing or as examples for production
// setup, not to generate production-ready configurations.
//
// When tactics key material is provided in GenerateConfigParams, tactics
// capabilities are added for all meek protocols in TunnelProtocolPorts.
func GenerateConfig(params *GenerateConfigParams) ([]byte, []byte, []byte, []byte, []byte, error) {

	// Input validation

	if net.ParseIP(params.ServerIPAddress) == nil {
		return nil, nil, nil, nil, nil, errors.TraceNew("invalid IP address")
	}

	if len(params.TunnelProtocolPorts) == 0 {
		return nil, nil, nil, nil, nil, errors.TraceNew("no tunnel protocols")
	}

	usedPort := make(map[int]bool)
	usingMeek := false
	usingTLSOSSH := false
	usingInproxy := false

	for tunnelProtocol, port := range params.TunnelProtocolPorts {

		if !common.Contains(protocol.SupportedTunnelProtocols, tunnelProtocol) {
			return nil, nil, nil, nil, nil, errors.TraceNew("invalid tunnel protocol")
		}

		if usedPort[port] {
			return nil, nil, nil, nil, nil, errors.TraceNew("duplicate listening port")
		}
		usedPort[port] = true

		if protocol.TunnelProtocolUsesTLSOSSH(tunnelProtocol) {
			usingTLSOSSH = true
		}

		if protocol.TunnelProtocolUsesMeekHTTP(tunnelProtocol) ||
			protocol.TunnelProtocolUsesMeekHTTPS(tunnelProtocol) {
			usingMeek = true
		}

		if protocol.TunnelProtocolUsesInproxy(tunnelProtocol) {
			usingInproxy = true
		}
	}

	// One test mode populates the tactics config file; this will generate
	// keys. Another test mode passes in existing keys to be used in the
	// server entry. Both the filename and existing keys cannot be passed in.
	if (params.TacticsConfigFilename != "") &&
		(params.TacticsRequestPublicKey != "" || params.TacticsRequestObfuscatedKey != "") {
		return nil, nil, nil, nil, nil, errors.TraceNew("invalid tactics parameters")
	}

	// SSH config

	rsaKey, err := rsa.GenerateKey(rand.Reader, SSH_RSA_HOST_KEY_BITS)
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Trace(err)
	}

	sshPrivateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		},
	)

	signer, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Trace(err)
	}

	sshPublicKey := signer.PublicKey()

	sshUserNameSuffixBytes, err := common.MakeSecureRandomBytes(SSH_USERNAME_SUFFIX_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Trace(err)
	}
	sshUserNameSuffix := hex.EncodeToString(sshUserNameSuffixBytes)

	sshUserName := "psiphon_" + sshUserNameSuffix

	sshPasswordBytes, err := common.MakeSecureRandomBytes(SSH_PASSWORD_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Trace(err)
	}
	sshPassword := hex.EncodeToString(sshPasswordBytes)

	sshServerVersion := "SSH-2.0-Psiphon"

	// Obfuscated SSH config

	obfuscatedSSHKeyBytes, err := common.MakeSecureRandomBytes(SSH_OBFUSCATED_KEY_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Trace(err)
	}
	obfuscatedSSHKey := hex.EncodeToString(obfuscatedSSHKeyBytes)

	// Meek config

	var meekCookieEncryptionPublicKey, meekCookieEncryptionPrivateKey, meekObfuscatedKey string

	if usingMeek {
		rawMeekCookieEncryptionPublicKey, rawMeekCookieEncryptionPrivateKey, err :=
			box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}

		meekCookieEncryptionPublicKey = base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPublicKey[:])
		meekCookieEncryptionPrivateKey = base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPrivateKey[:])
	}

	if usingMeek || usingTLSOSSH {
		meekObfuscatedKeyBytes, err := common.MakeSecureRandomBytes(SSH_OBFUSCATED_KEY_BYTE_LENGTH)
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}
		meekObfuscatedKey = hex.EncodeToString(meekObfuscatedKeyBytes)
	}

	// Inproxy config

	var inproxyServerSessionPublicKey,
		inproxyServerSessionPrivateKey,
		inproxyServerObfuscationRootSecret string

	if usingInproxy {
		privateKey, err := inproxy.GenerateSessionPrivateKey()
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}
		inproxyServerSessionPrivateKey = privateKey.String()
		publicKey, err := privateKey.GetPublicKey()
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}
		inproxyServerSessionPublicKey = publicKey.String()
		obfuscationRootSecret, err := inproxy.GenerateRootObfuscationSecret()
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}
		inproxyServerObfuscationRootSecret = obfuscationRootSecret.String()
	}

	// Other config

	discoveryValueHMACKeyBytes, err := common.MakeSecureRandomBytes(DISCOVERY_VALUE_KEY_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Trace(err)
	}
	discoveryValueHMACKey := base64.StdEncoding.EncodeToString(discoveryValueHMACKeyBytes)

	// Generate a legacy web server secret, to accomodate test cases, such as deriving
	// a server entry tag when no tag is present.
	webServerSecretBytes, err := common.MakeSecureRandomBytes(WEB_SERVER_SECRET_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Trace(err)
	}
	webServerSecret := hex.EncodeToString(webServerSecretBytes)

	// Assemble configs and server entry

	// Note: this config is intended for either testing or as an illustrative
	// example or template and is not intended for production deployment.

	logLevel := params.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}

	// For testing, set the Psiphon server to create its log files; we do not
	// expect tests to necessarily run under log managers, such as logrotate.
	createMode := 0666

	config := &Config{
		LogLevel:                           logLevel,
		LogFilename:                        params.LogFilename,
		LogFileCreateMode:                  &createMode,
		SkipPanickingLogWriter:             params.SkipPanickingLogWriter,
		GeoIPDatabaseFilenames:             nil,
		HostID:                             "example-host-id",
		ServerIPAddress:                    params.ServerIPAddress,
		DiscoveryValueHMACKey:              discoveryValueHMACKey,
		SSHPrivateKey:                      string(sshPrivateKey),
		SSHServerVersion:                   sshServerVersion,
		SSHUserName:                        sshUserName,
		SSHPassword:                        sshPassword,
		ObfuscatedSSHKey:                   obfuscatedSSHKey,
		TunnelProtocolPorts:                params.TunnelProtocolPorts,
		TunnelProtocolPassthroughAddresses: params.TunnelProtocolPassthroughAddresses,
		DNSResolverIPAddress:               "8.8.8.8",
		UDPInterceptUdpgwServerAddress:     "127.0.0.1:7300",
		MeekCookieEncryptionPrivateKey:     meekCookieEncryptionPrivateKey,
		MeekObfuscatedKey:                  meekObfuscatedKey,
		MeekProhibitedHeaders:              nil,
		MeekProxyForwardedForHeaders:       []string{"X-Forwarded-For"},
		LoadMonitorPeriodSeconds:           300,
		TrafficRulesFilename:               params.TrafficRulesConfigFilename,
		OSLConfigFilename:                  params.OSLConfigFilename,
		TacticsConfigFilename:              params.TacticsConfigFilename,
		LegacyPassthrough:                  params.LegacyPassthrough,
		EnableGQUIC:                        params.EnableGQUIC,
		InproxyServerSessionPrivateKey:     inproxyServerSessionPrivateKey,
		InproxyServerObfuscationRootSecret: inproxyServerObfuscationRootSecret,
	}

	encodedConfig, err := json.MarshalIndent(config, "\n", "    ")
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Trace(err)
	}

	intPtr := func(i int) *int {
		return &i
	}

	trafficRulesSet := &TrafficRulesSet{
		DefaultRules: TrafficRules{
			RateLimits: RateLimits{
				ReadUnthrottledBytes:  new(int64),
				ReadBytesPerSecond:    new(int64),
				WriteUnthrottledBytes: new(int64),
				WriteBytesPerSecond:   new(int64),
			},
			IdleTCPPortForwardTimeoutMilliseconds: intPtr(DEFAULT_IDLE_TCP_PORT_FORWARD_TIMEOUT_MILLISECONDS),
			IdleUDPPortForwardTimeoutMilliseconds: intPtr(DEFAULT_IDLE_UDP_PORT_FORWARD_TIMEOUT_MILLISECONDS),
			MaxTCPPortForwardCount:                intPtr(DEFAULT_MAX_TCP_PORT_FORWARD_COUNT),
			MaxUDPPortForwardCount:                intPtr(DEFAULT_MAX_UDP_PORT_FORWARD_COUNT),
			AllowTCPPorts:                         nil,
			AllowUDPPorts:                         nil,
		},
	}

	encodedTrafficRulesSet, err := json.MarshalIndent(trafficRulesSet, "\n", "    ")
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Trace(err)
	}

	encodedOSLConfig, err := json.MarshalIndent(&osl.Config{}, "\n", "    ")
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Trace(err)
	}

	tacticsRequestPublicKey := params.TacticsRequestPublicKey
	tacticsRequestObfuscatedKey := params.TacticsRequestObfuscatedKey
	var tacticsRequestPrivateKey string
	var encodedTacticsConfig []byte

	if params.TacticsConfigFilename != "" {

		tacticsRequestPublicKey, tacticsRequestPrivateKey, tacticsRequestObfuscatedKey, err =
			tactics.GenerateKeys()
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}

		decodedTacticsRequestPublicKey, err := base64.StdEncoding.DecodeString(tacticsRequestPublicKey)
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}

		decodedTacticsRequestPrivateKey, err := base64.StdEncoding.DecodeString(tacticsRequestPrivateKey)
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}

		decodedTacticsRequestObfuscatedKey, err := base64.StdEncoding.DecodeString(tacticsRequestObfuscatedKey)
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}

		tacticsConfig := &tactics.Server{
			RequestPublicKey:     decodedTacticsRequestPublicKey,
			RequestPrivateKey:    decodedTacticsRequestPrivateKey,
			RequestObfuscatedKey: decodedTacticsRequestObfuscatedKey,
			DefaultTactics: tactics.Tactics{
				TTL: "1m",
			},
		}

		encodedTacticsConfig, err = json.MarshalIndent(tacticsConfig, "\n", "    ")
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}
	}

	// Capabilities

	capabilities := []string{protocol.CAPABILITY_SSH_API_REQUESTS}

	var frontingProviderID string

	for tunnelProtocol := range params.TunnelProtocolPorts {

		capability := protocol.GetCapability(tunnelProtocol)

		// In-proxy tunnel protocol capabilities don't include
		// v1/-PASSTHROUGHv2 suffixes; see comments in ServerEntry.hasCapability.
		if !protocol.TunnelProtocolUsesInproxy(tunnelProtocol) {

			// Note: do not add passthrough annotation if HTTP unfronted meek
			// because it would result in an invalid capability.
			if params.Passthrough &&
				protocol.TunnelProtocolSupportsPassthrough(tunnelProtocol) &&
				tunnelProtocol != protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK {

				if !params.LegacyPassthrough {
					capability += "-PASSTHROUGH-v2"
				} else {
					capability += "-PASSTHROUGH"
				}
			}

			if tunnelProtocol == protocol.TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH &&
				!params.EnableGQUIC {

				capability += "v1"
			}
		}

		capabilities = append(capabilities, capability)

		if params.TacticsRequestPublicKey != "" && params.TacticsRequestObfuscatedKey != "" &&
			protocol.TunnelProtocolSupportsTactics(tunnelProtocol) {

			capabilities = append(capabilities, protocol.GetTacticsCapability(tunnelProtocol))
		}

		if protocol.TunnelProtocolUsesFrontedMeek(tunnelProtocol) {
			frontingProviderID = params.FrontingProviderID
		}
	}

	// Tunnel protocol ports

	// Limitations:
	// - Only one meek port may be specified per server entry.
	// - Neither fronted meek nor Conjuure protocols are supported here.

	var sshPort, obfuscatedSSHPort, meekPort, obfuscatedSSHQUICPort, tlsOSSHPort int
	var inproxySSHPort, inproxyOSSHPort, inproxyQUICPort, inproxyMeekPort, inproxyTlsOSSHPort int

	for tunnelProtocol, port := range params.TunnelProtocolPorts {

		if !protocol.TunnelProtocolUsesInproxy(tunnelProtocol) {
			switch tunnelProtocol {
			case protocol.TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH:
				tlsOSSHPort = port
			case protocol.TUNNEL_PROTOCOL_SSH:
				sshPort = port
			case protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH:
				obfuscatedSSHPort = port
			case protocol.TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH:
				obfuscatedSSHQUICPort = port
			case protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
				protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET,
				protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK:
				meekPort = port
			}
		} else {
			switch protocol.TunnelProtocolMinusInproxy(tunnelProtocol) {
			case protocol.TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH:
				inproxyTlsOSSHPort = port
			case protocol.TUNNEL_PROTOCOL_SSH:
				inproxySSHPort = port
			case protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH:
				inproxyOSSHPort = port
			case protocol.TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH:
				inproxyQUICPort = port
			case protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
				protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET,
				protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK:
				inproxyMeekPort = port
			}
		}
	}

	// Note: fronting params are a stub; this server entry will exercise
	// client and server fronting code paths, but not actually traverse
	// a fronting hop.

	serverEntry := &protocol.ServerEntry{
		Tag:                                 prng.Base64String(32),
		IpAddress:                           params.ServerIPAddress,
		WebServerSecret:                     webServerSecret,
		TlsOSSHPort:                         tlsOSSHPort,
		SshPort:                             sshPort,
		SshUsername:                         sshUserName,
		SshPassword:                         sshPassword,
		SshHostKey:                          base64.RawStdEncoding.EncodeToString(sshPublicKey.Marshal()),
		SshObfuscatedPort:                   obfuscatedSSHPort,
		SshObfuscatedQUICPort:               obfuscatedSSHQUICPort,
		LimitQUICVersions:                   params.LimitQUICVersions,
		SshObfuscatedKey:                    obfuscatedSSHKey,
		Capabilities:                        capabilities,
		Region:                              "US",
		ProviderID:                          strings.ToUpper(prng.HexString(8)),
		FrontingProviderID:                  frontingProviderID,
		MeekServerPort:                      meekPort,
		MeekCookieEncryptionPublicKey:       meekCookieEncryptionPublicKey,
		MeekObfuscatedKey:                   meekObfuscatedKey,
		MeekFrontingHosts:                   []string{params.ServerIPAddress},
		MeekFrontingAddresses:               []string{params.ServerIPAddress},
		MeekFrontingDisableSNI:              false,
		TacticsRequestPublicKey:             tacticsRequestPublicKey,
		TacticsRequestObfuscatedKey:         tacticsRequestObfuscatedKey,
		ConfigurationVersion:                1,
		InproxySessionPublicKey:             inproxyServerSessionPublicKey,
		InproxySessionRootObfuscationSecret: inproxyServerObfuscationRootSecret,
		InproxySSHPort:                      inproxySSHPort,
		InproxyOSSHPort:                     inproxyOSSHPort,
		InproxyQUICPort:                     inproxyQUICPort,
		InproxyMeekPort:                     inproxyMeekPort,
		InproxyTlsOSSHPort:                  inproxyTlsOSSHPort,
	}

	if params.ServerEntrySignaturePublicKey != "" {
		serverEntryJSON, err := json.Marshal(serverEntry)
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}
		var serverEntryFields protocol.ServerEntryFields
		err = json.Unmarshal(serverEntryJSON, &serverEntryFields)
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}
		err = serverEntryFields.AddSignature(
			params.ServerEntrySignaturePublicKey, params.ServerEntrySignaturePrivateKey)
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}

		serverEntry, err = serverEntryFields.GetServerEntry()
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Trace(err)
		}
	}

	encodedServerEntry, err := protocol.EncodeServerEntry(serverEntry)
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Trace(err)
	}

	return encodedConfig, encodedTrafficRulesSet, encodedOSLConfig, encodedTacticsConfig, []byte(encodedServerEntry), nil
}
