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
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/accesscontrol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/nacl/box"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
)

const (
	SERVER_CONFIG_FILENAME               = "psiphond.config"
	SERVER_TRAFFIC_RULES_CONFIG_FILENAME = "psiphond-traffic-rules.config"
	SERVER_OSL_CONFIG_FILENAME           = "psiphond-osl.config"
	SERVER_TACTICS_CONFIG_FILENAME       = "psiphond-tactics.config"
	SERVER_ENTRY_FILENAME                = "server-entry.dat"
	DEFAULT_SERVER_IP_ADDRESS            = "127.0.0.1"
	WEB_SERVER_SECRET_BYTE_LENGTH        = 32
	DISCOVERY_VALUE_KEY_BYTE_LENGTH      = 32
	SSH_USERNAME_SUFFIX_BYTE_LENGTH      = 8
	SSH_PASSWORD_BYTE_LENGTH             = 32
	SSH_RSA_HOST_KEY_BITS                = 2048
	SSH_OBFUSCATED_KEY_BYTE_LENGTH       = 32
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

	// PsinetDatabaseFilename is the path of the Psiphon automation
	// jsonpickle format Psiphon API data file.
	PsinetDatabaseFilename string

	// HostID is the ID of the server host; this is used for API
	// event logging.
	HostID string

	// ServerIPAddress is the public IP address of the server.
	ServerIPAddress string

	// WebServerPort is the listening port of the web server.
	// When <= 0, no web server component is run.
	WebServerPort int

	// WebServerSecret is the unique secret value that the client
	// must supply to make requests to the web server.
	WebServerSecret string

	// WebServerCertificate is the certificate the client uses to
	// authenticate the web server.
	WebServerCertificate string

	// WebServerPrivateKey is the private key the web server uses to
	// authenticate itself to clients.
	WebServerPrivateKey string

	// WebServerPortForwardAddress specifies the expected network
	// address ("<host>:<port>") specified in a client's port forward
	// HostToConnect and PortToConnect when the client is making a
	// tunneled connection to the web server. This address is always
	// exempted from validation against SSH_DISALLOWED_PORT_FORWARD_HOSTS
	// and AllowTCPPorts.
	WebServerPortForwardAddress string

	// WebServerPortForwardRedirectAddress specifies an alternate
	// destination address to be substituted and dialed instead of
	// the original destination when the port forward destination is
	// WebServerPortForwardAddress.
	WebServerPortForwardRedirectAddress string

	// TunnelProtocolPorts specifies which tunnel protocols to run
	// and which ports to listen on for each protocol. Valid tunnel
	// protocols include:
	// "SSH", "OSSH", "UNFRONTED-MEEK-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH",
	// "UNFRONTED-MEEK-SESSION-TICKET-OSSH", "FRONTED-MEEK-OSSH",
	// "FRONTED-MEEK-HTTP-OSSH", "QUIC-OSSH", "MARIONETTE-OSSH", and
	// "TAPDANCE-OSSH".
	//
	// In the case of "MARIONETTE-OSSH" the port value is ignored and must be
	// set to 0. The port value specified in the Marionette format is used.
	TunnelProtocolPorts map[string]int

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
	MeekObfuscatedKey string

	// MeekProhibitedHeaders is a list of HTTP headers to check for
	// in client requests. If one of these headers is found, the
	// request fails. This is used to defend against abuse.
	MeekProhibitedHeaders []string

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

	// PacketTunnelDownstreamPacketQueueSize specifies
	// tun.ServerConfig.DownStreamPacketQueueSize.
	PacketTunnelDownstreamPacketQueueSize int

	// PacketTunnelSessionIdleExpirySeconds specifies
	// tun.ServerConfig.SessionIdleExpirySeconds.
	PacketTunnelSessionIdleExpirySeconds int

	// PacketTunnelSudoNetworkConfigCommands sets
	// tun.ServerConfig.SudoNetworkConfigCommands.
	PacketTunnelSudoNetworkConfigCommands bool

	// MaxConcurrentSSHHandshakes specifies a limit on the number of concurrent
	// SSH handshake negotiations. This is set to mitigate spikes in memory
	// allocations and CPU usage associated with SSH handshakes when many clients
	// attempt to connect concurrently. When a maximum limit is specified and
	// reached, additional clients that establish TCP or meek connections will
	// be disconnected after a short wait for the number of concurrent handshakes
	// to drop below the limit.
	// The default, 0 is no limit.
	MaxConcurrentSSHHandshakes int

	// PeriodicGarbageCollectionSeconds turns on periodic calls to runtime.GC,
	// every specified number of seconds, to force garbage collection.
	// The default, 0 is off.
	PeriodicGarbageCollectionSeconds int

	// AccessControlVerificationKeyRing is the access control authorization
	// verification key ring used to verify signed authorizations presented
	// by clients. Verified, active (unexpired) access control types will be
	// available for matching in the TrafficRulesFilter for the client via
	// AuthorizedAccessTypes. All other authorizations are ignored.
	AccessControlVerificationKeyRing accesscontrol.VerificationKeyRing

	// TacticsConfigFilename is the path of a file containing a JSON-encoded
	// tactics server configuration.
	TacticsConfigFilename string

	// MarionetteFormat specifies a Marionette format to use with the
	// MARIONETTE-OSSH tunnel protocol. The format specifies the network
	// protocol port to listen on.
	MarionetteFormat string

	// BlocklistFilename is the path of a file containing a CSV-encoded
	// blocklist configuration. See NewBlocklist for more file format
	// documentation.
	BlocklistFilename string

	// BlocklistActive indicates whether to actively prevent blocklist hits in
	// addition to logging events.
	BlocklistActive bool

	sshBeginHandshakeTimeout time.Duration
	sshHandshakeTimeout      time.Duration
}

// RunWebServer indicates whether to run a web server component.
func (config *Config) RunWebServer() bool {
	return config.WebServerPort > 0
}

// RunLoadMonitor indicates whether to monitor and log server load.
func (config *Config) RunLoadMonitor() bool {
	return config.LoadMonitorPeriodSeconds > 0
}

// RunPeriodicGarbageCollection indicates whether to run periodic garbage collection.
func (config *Config) RunPeriodicGarbageCollection() bool {
	return config.PeriodicGarbageCollectionSeconds > 0
}

// LoadConfig loads and validates a JSON encoded server config.
func LoadConfig(configJSON []byte) (*Config, error) {

	var config Config
	err := json.Unmarshal(configJSON, &config)
	if err != nil {
		return nil, common.ContextError(err)
	}

	if config.ServerIPAddress == "" {
		return nil, errors.New("ServerIPAddress is required")
	}

	if config.WebServerPort > 0 && (config.WebServerSecret == "" || config.WebServerCertificate == "" ||
		config.WebServerPrivateKey == "") {

		return nil, errors.New(
			"Web server requires WebServerSecret, WebServerCertificate, WebServerPrivateKey")
	}

	if config.WebServerPortForwardAddress != "" {
		if err := validateNetworkAddress(config.WebServerPortForwardAddress, false); err != nil {
			return nil, errors.New("WebServerPortForwardAddress is invalid")
		}
	}

	if config.WebServerPortForwardRedirectAddress != "" {

		if config.WebServerPortForwardAddress == "" {
			return nil, errors.New(
				"WebServerPortForwardRedirectAddress requires WebServerPortForwardAddress")
		}

		if err := validateNetworkAddress(config.WebServerPortForwardRedirectAddress, false); err != nil {
			return nil, errors.New("WebServerPortForwardRedirectAddress is invalid")
		}
	}

	for tunnelProtocol, port := range config.TunnelProtocolPorts {
		if !common.Contains(protocol.SupportedTunnelProtocols, tunnelProtocol) {
			return nil, fmt.Errorf("Unsupported tunnel protocol: %s", tunnelProtocol)
		}
		if protocol.TunnelProtocolUsesSSH(tunnelProtocol) ||
			protocol.TunnelProtocolUsesObfuscatedSSH(tunnelProtocol) {
			if config.SSHPrivateKey == "" || config.SSHServerVersion == "" ||
				config.SSHUserName == "" || config.SSHPassword == "" {
				return nil, fmt.Errorf(
					"Tunnel protocol %s requires SSHPrivateKey, SSHServerVersion, SSHUserName, SSHPassword",
					tunnelProtocol)
			}
		}
		if protocol.TunnelProtocolUsesObfuscatedSSH(tunnelProtocol) {
			if config.ObfuscatedSSHKey == "" {
				return nil, fmt.Errorf(
					"Tunnel protocol %s requires ObfuscatedSSHKey",
					tunnelProtocol)
			}
		}
		if protocol.TunnelProtocolUsesMeekHTTP(tunnelProtocol) ||
			protocol.TunnelProtocolUsesMeekHTTPS(tunnelProtocol) {
			if config.MeekCookieEncryptionPrivateKey == "" || config.MeekObfuscatedKey == "" {
				return nil, fmt.Errorf(
					"Tunnel protocol %s requires MeekCookieEncryptionPrivateKey, MeekObfuscatedKey",
					tunnelProtocol)
			}
		}
		if protocol.TunnelProtocolUsesMarionette(tunnelProtocol) {
			if port != 0 {
				return nil, fmt.Errorf(
					"Tunnel protocol %s port is specified in format, not TunnelProtocolPorts",
					tunnelProtocol)
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
			return nil, fmt.Errorf(
				"DeriveSSHServerVersionPRNGSeed failed: %s", err)
		}

		serverVersion := pickSSHServerVersion(seed)
		if serverVersion != "" {
			config.SSHServerVersion = serverVersion
		}
	}

	if config.UDPInterceptUdpgwServerAddress != "" {
		if err := validateNetworkAddress(config.UDPInterceptUdpgwServerAddress, true); err != nil {
			return nil, fmt.Errorf("UDPInterceptUdpgwServerAddress is invalid: %s", err)
		}
	}

	if config.DNSResolverIPAddress != "" {
		if net.ParseIP(config.DNSResolverIPAddress) == nil {
			return nil, fmt.Errorf("DNSResolverIPAddress is invalid")
		}
	}

	err = accesscontrol.ValidateVerificationKeyRing(&config.AccessControlVerificationKeyRing)
	if err != nil {
		return nil, fmt.Errorf(
			"AccessControlVerificationKeyRing is invalid: %s", err)
	}

	return &config, nil
}

func validateNetworkAddress(address string, requireIPaddress bool) error {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if requireIPaddress && net.ParseIP(host) == nil {
		return errors.New("host must be an IP address")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	if port < 0 || port > 65535 {
		return errors.New("invalid port")
	}
	return nil
}

// GenerateConfigParams specifies customizations to be applied to
// a generated server config.
type GenerateConfigParams struct {
	LogFilename                 string
	SkipPanickingLogWriter      bool
	LogLevel                    string
	ServerIPAddress             string
	WebServerPort               int
	EnableSSHAPIRequests        bool
	TunnelProtocolPorts         map[string]int
	MarionetteFormat            string
	TrafficRulesConfigFilename  string
	OSLConfigFilename           string
	TacticsConfigFilename       string
	TacticsRequestPublicKey     string
	TacticsRequestObfuscatedKey string
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
		return nil, nil, nil, nil, nil, common.ContextError(errors.New("invalid IP address"))
	}

	if len(params.TunnelProtocolPorts) == 0 {
		return nil, nil, nil, nil, nil, common.ContextError(errors.New("no tunnel protocols"))
	}

	usedPort := make(map[int]bool)
	if params.WebServerPort != 0 {
		usedPort[params.WebServerPort] = true
	}

	usingMeek := false

	for tunnelProtocol, port := range params.TunnelProtocolPorts {

		if !common.Contains(protocol.SupportedTunnelProtocols, tunnelProtocol) {
			return nil, nil, nil, nil, nil, common.ContextError(errors.New("invalid tunnel protocol"))
		}

		if usedPort[port] {
			return nil, nil, nil, nil, nil, common.ContextError(errors.New("duplicate listening port"))
		}
		usedPort[port] = true

		if protocol.TunnelProtocolUsesMeekHTTP(tunnelProtocol) ||
			protocol.TunnelProtocolUsesMeekHTTPS(tunnelProtocol) {
			usingMeek = true
		}
	}

	// One test mode populates the tactics config file; this will generate
	// keys. Another test mode passes in existing keys to be used in the
	// server entry. Both the filename and existing keys cannot be passed in.
	if (params.TacticsConfigFilename != "") &&
		(params.TacticsRequestPublicKey != "" || params.TacticsRequestObfuscatedKey != "") {
		return nil, nil, nil, nil, nil, common.ContextError(errors.New("invalid tactics parameters"))
	}

	// Web server config

	var webServerSecret, webServerCertificate,
		webServerPrivateKey, webServerPortForwardAddress string

	if params.WebServerPort != 0 {
		webServerSecretBytes, err := common.MakeSecureRandomBytes(WEB_SERVER_SECRET_BYTE_LENGTH)
		if err != nil {
			return nil, nil, nil, nil, nil, common.ContextError(err)
		}
		webServerSecret = hex.EncodeToString(webServerSecretBytes)

		webServerCertificate, webServerPrivateKey, err = common.GenerateWebServerCertificate("")
		if err != nil {
			return nil, nil, nil, nil, nil, common.ContextError(err)
		}

		webServerPortForwardAddress = net.JoinHostPort(
			params.ServerIPAddress, strconv.Itoa(params.WebServerPort))
	}

	// SSH config

	rsaKey, err := rsa.GenerateKey(rand.Reader, SSH_RSA_HOST_KEY_BITS)
	if err != nil {
		return nil, nil, nil, nil, nil, common.ContextError(err)
	}

	sshPrivateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		},
	)

	signer, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		return nil, nil, nil, nil, nil, common.ContextError(err)
	}

	sshPublicKey := signer.PublicKey()

	sshUserNameSuffixBytes, err := common.MakeSecureRandomBytes(SSH_USERNAME_SUFFIX_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, nil, nil, common.ContextError(err)
	}
	sshUserNameSuffix := hex.EncodeToString(sshUserNameSuffixBytes)

	sshUserName := "psiphon_" + sshUserNameSuffix

	sshPasswordBytes, err := common.MakeSecureRandomBytes(SSH_PASSWORD_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, nil, nil, common.ContextError(err)
	}
	sshPassword := hex.EncodeToString(sshPasswordBytes)

	sshServerVersion := "SSH-2.0-Psiphon"

	// Obfuscated SSH config

	obfuscatedSSHKeyBytes, err := common.MakeSecureRandomBytes(SSH_OBFUSCATED_KEY_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, nil, nil, common.ContextError(err)
	}
	obfuscatedSSHKey := hex.EncodeToString(obfuscatedSSHKeyBytes)

	// Meek config

	var meekCookieEncryptionPublicKey, meekCookieEncryptionPrivateKey, meekObfuscatedKey string

	if usingMeek {
		rawMeekCookieEncryptionPublicKey, rawMeekCookieEncryptionPrivateKey, err :=
			box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, nil, nil, common.ContextError(err)
		}

		meekCookieEncryptionPublicKey = base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPublicKey[:])
		meekCookieEncryptionPrivateKey = base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPrivateKey[:])

		meekObfuscatedKeyBytes, err := common.MakeSecureRandomBytes(SSH_OBFUSCATED_KEY_BYTE_LENGTH)
		if err != nil {
			return nil, nil, nil, nil, nil, common.ContextError(err)
		}
		meekObfuscatedKey = hex.EncodeToString(meekObfuscatedKeyBytes)
	}

	// Other config

	discoveryValueHMACKeyBytes, err := common.MakeSecureRandomBytes(DISCOVERY_VALUE_KEY_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, nil, nil, common.ContextError(err)
	}
	discoveryValueHMACKey := base64.RawURLEncoding.EncodeToString(discoveryValueHMACKeyBytes)

	// Assemble configs and server entry

	// Note: this config is intended for either testing or as an illustrative
	// example or template and is not intended for production deployment.

	logLevel := params.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}

	config := &Config{
		LogLevel:                       logLevel,
		LogFilename:                    params.LogFilename,
		SkipPanickingLogWriter:         params.SkipPanickingLogWriter,
		GeoIPDatabaseFilenames:         nil,
		HostID:                         "example-host-id",
		ServerIPAddress:                params.ServerIPAddress,
		DiscoveryValueHMACKey:          discoveryValueHMACKey,
		WebServerPort:                  params.WebServerPort,
		WebServerSecret:                webServerSecret,
		WebServerCertificate:           webServerCertificate,
		WebServerPrivateKey:            webServerPrivateKey,
		WebServerPortForwardAddress:    webServerPortForwardAddress,
		SSHPrivateKey:                  string(sshPrivateKey),
		SSHServerVersion:               sshServerVersion,
		SSHUserName:                    sshUserName,
		SSHPassword:                    sshPassword,
		ObfuscatedSSHKey:               obfuscatedSSHKey,
		TunnelProtocolPorts:            params.TunnelProtocolPorts,
		DNSResolverIPAddress:           "8.8.8.8",
		UDPInterceptUdpgwServerAddress: "127.0.0.1:7300",
		MeekCookieEncryptionPrivateKey: meekCookieEncryptionPrivateKey,
		MeekObfuscatedKey:              meekObfuscatedKey,
		MeekProhibitedHeaders:          nil,
		MeekProxyForwardedForHeaders:   []string{"X-Forwarded-For"},
		LoadMonitorPeriodSeconds:       300,
		TrafficRulesFilename:           params.TrafficRulesConfigFilename,
		OSLConfigFilename:              params.OSLConfigFilename,
		TacticsConfigFilename:          params.TacticsConfigFilename,
		MarionetteFormat:               params.MarionetteFormat,
	}

	encodedConfig, err := json.MarshalIndent(config, "\n", "    ")
	if err != nil {
		return nil, nil, nil, nil, nil, common.ContextError(err)
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
		return nil, nil, nil, nil, nil, common.ContextError(err)
	}

	encodedOSLConfig, err := json.MarshalIndent(&osl.Config{}, "\n", "    ")
	if err != nil {
		return nil, nil, nil, nil, nil, common.ContextError(err)
	}

	tacticsRequestPublicKey := params.TacticsRequestPublicKey
	tacticsRequestObfuscatedKey := params.TacticsRequestObfuscatedKey
	var tacticsRequestPrivateKey string
	var encodedTacticsConfig []byte

	if params.TacticsConfigFilename != "" {

		tacticsRequestPublicKey, tacticsRequestPrivateKey, tacticsRequestObfuscatedKey, err =
			tactics.GenerateKeys()
		if err != nil {
			return nil, nil, nil, nil, nil, common.ContextError(err)
		}

		decodedTacticsRequestPublicKey, err := base64.StdEncoding.DecodeString(tacticsRequestPublicKey)
		if err != nil {
			return nil, nil, nil, nil, nil, common.ContextError(err)
		}

		decodedTacticsRequestPrivateKey, err := base64.StdEncoding.DecodeString(tacticsRequestPrivateKey)
		if err != nil {
			return nil, nil, nil, nil, nil, common.ContextError(err)
		}

		decodedTacticsRequestObfuscatedKey, err := base64.StdEncoding.DecodeString(tacticsRequestObfuscatedKey)
		if err != nil {
			return nil, nil, nil, nil, nil, common.ContextError(err)
		}

		tacticsConfig := &tactics.Server{
			RequestPublicKey:     decodedTacticsRequestPublicKey,
			RequestPrivateKey:    decodedTacticsRequestPrivateKey,
			RequestObfuscatedKey: decodedTacticsRequestObfuscatedKey,
			DefaultTactics: tactics.Tactics{
				TTL:         "1m",
				Probability: 1.0,
			},
		}

		encodedTacticsConfig, err = json.MarshalIndent(tacticsConfig, "\n", "    ")
		if err != nil {
			return nil, nil, nil, nil, nil, common.ContextError(err)
		}
	}

	capabilities := []string{}

	if params.EnableSSHAPIRequests {
		capabilities = append(capabilities, protocol.CAPABILITY_SSH_API_REQUESTS)
	}

	if params.WebServerPort != 0 {
		capabilities = append(capabilities, protocol.CAPABILITY_UNTUNNELED_WEB_API_REQUESTS)
	}

	for tunnelProtocol := range params.TunnelProtocolPorts {
		capabilities = append(capabilities, protocol.GetCapability(tunnelProtocol))

		if params.TacticsRequestPublicKey != "" && params.TacticsRequestObfuscatedKey != "" &&
			protocol.TunnelProtocolUsesMeek(tunnelProtocol) {

			capabilities = append(capabilities, protocol.GetTacticsCapability(tunnelProtocol))
		}
	}

	sshPort := params.TunnelProtocolPorts["SSH"]
	obfuscatedSSHPort := params.TunnelProtocolPorts["OSSH"]
	obfuscatedSSHQUICPort := params.TunnelProtocolPorts["QUIC-OSSH"]

	// Meek port limitations
	// - fronted meek protocols are hard-wired in the client to be port 443 or 80.
	// - only one other meek port may be specified.
	meekPort := params.TunnelProtocolPorts["UNFRONTED-MEEK-OSSH"]
	if meekPort == 0 {
		meekPort = params.TunnelProtocolPorts["UNFRONTED-MEEK-HTTPS-OSSH"]
	}
	if meekPort == 0 {
		meekPort = params.TunnelProtocolPorts["UNFRONTED-MEEK-SESSION-TICKET-OSSH"]
	}

	// Note: fronting params are a stub; this server entry will exercise
	// client and server fronting code paths, but not actually traverse
	// a fronting hop.

	serverEntryWebServerPort := ""
	strippedWebServerCertificate := ""

	if params.WebServerPort != 0 {
		serverEntryWebServerPort = fmt.Sprintf("%d", params.WebServerPort)

		// Server entry format omits the BEGIN/END lines and newlines
		lines := strings.Split(webServerCertificate, "\n")
		strippedWebServerCertificate = strings.Join(lines[1:len(lines)-2], "")
	}

	serverEntry := &protocol.ServerEntry{
		IpAddress:                     params.ServerIPAddress,
		WebServerPort:                 serverEntryWebServerPort,
		WebServerSecret:               webServerSecret,
		WebServerCertificate:          strippedWebServerCertificate,
		SshPort:                       sshPort,
		SshUsername:                   sshUserName,
		SshPassword:                   sshPassword,
		SshHostKey:                    base64.RawStdEncoding.EncodeToString(sshPublicKey.Marshal()),
		SshObfuscatedPort:             obfuscatedSSHPort,
		SshObfuscatedQUICPort:         obfuscatedSSHQUICPort,
		SshObfuscatedKey:              obfuscatedSSHKey,
		Capabilities:                  capabilities,
		Region:                        "US",
		MeekServerPort:                meekPort,
		MeekCookieEncryptionPublicKey: meekCookieEncryptionPublicKey,
		MeekObfuscatedKey:             meekObfuscatedKey,
		MeekFrontingHosts:             []string{params.ServerIPAddress},
		MeekFrontingAddresses:         []string{params.ServerIPAddress},
		MeekFrontingDisableSNI:        false,
		TacticsRequestPublicKey:       tacticsRequestPublicKey,
		TacticsRequestObfuscatedKey:   tacticsRequestObfuscatedKey,
		MarionetteFormat:              params.MarionetteFormat,
		ConfigurationVersion:          1,
	}

	encodedServerEntry, err := protocol.EncodeServerEntry(serverEntry)
	if err != nil {
		return nil, nil, nil, nil, nil, common.ContextError(err)
	}

	return encodedConfig, encodedTrafficRulesSet, encodedOSLConfig, encodedTacticsConfig, []byte(encodedServerEntry), nil
}
