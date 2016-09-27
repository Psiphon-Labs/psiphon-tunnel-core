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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Psiphon-Inc/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"golang.org/x/crypto/nacl/box"
)

const (
	SERVER_CONFIG_FILENAME          = "psiphond.config"
	SERVER_TRAFFIC_RULES_FILENAME   = "psiphond-traffic-rules.config"
	SERVER_ENTRY_FILENAME           = "server-entry.dat"
	DEFAULT_SERVER_IP_ADDRESS       = "127.0.0.1"
	WEB_SERVER_SECRET_BYTE_LENGTH   = 32
	DISCOVERY_VALUE_KEY_BYTE_LENGTH = 32
	SSH_USERNAME_SUFFIX_BYTE_LENGTH = 8
	SSH_PASSWORD_BYTE_LENGTH        = 32
	SSH_RSA_HOST_KEY_BITS           = 2048
	SSH_OBFUSCATED_KEY_BYTE_LENGTH  = 32
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

	// DiscoveryValueHMACKey is the network-wide secret value
	// used to determine a unique discovery strategy.
	DiscoveryValueHMACKey string

	// GeoIPDatabaseFilenames ares paths of GeoIP2/GeoLite2
	// MaxMind database files. When empty, no GeoIP lookups are
	// performed. Each file is queried, in order, for the
	// logged fields: country code, city, and ISP. Multiple
	// file support accomodates the MaxMind distribution where
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
	// protocols include: "SSH", "OSSH", "UNFRONTED-MEEK-OSSH",
	// "UNFRONTED-MEEK-HTTPS-OSSH", "FRONTED-MEEK-OSSH",
	// "FRONTED-MEEK-HTTP-OSSH".
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

	// MeekCertificateCommonName is the value used for the hostname
	// in the self-signed certificate generated and used for meek
	// HTTPS modes. The same value is used for all HTTPS meek
	// protocols.
	MeekCertificateCommonName string

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

	// TrafficRulesFilename is the path of a file containing a
	// JSON-encoded TrafficRulesSet, the traffic rules to apply to
	// Psiphon client tunnels.
	TrafficRulesFilename string
}

// RunWebServer indicates whether to run a web server component.
func (config *Config) RunWebServer() bool {
	return config.WebServerPort > 0
}

// RunLoadMonitor indicates whether to monitor and log server load.
func (config *Config) RunLoadMonitor() bool {
	return config.LoadMonitorPeriodSeconds > 0
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

	for tunnelProtocol, _ := range config.TunnelProtocolPorts {
		if !common.Contains(common.SupportedTunnelProtocols, tunnelProtocol) {
			return nil, fmt.Errorf("Unsupported tunnel protocol: %s", tunnelProtocol)
		}
		if common.TunnelProtocolUsesSSH(tunnelProtocol) ||
			common.TunnelProtocolUsesObfuscatedSSH(tunnelProtocol) {
			if config.SSHPrivateKey == "" || config.SSHServerVersion == "" ||
				config.SSHUserName == "" || config.SSHPassword == "" {
				return nil, fmt.Errorf(
					"Tunnel protocol %s requires SSHPrivateKey, SSHServerVersion, SSHUserName, SSHPassword",
					tunnelProtocol)
			}
		}
		if common.TunnelProtocolUsesObfuscatedSSH(tunnelProtocol) {
			if config.ObfuscatedSSHKey == "" {
				return nil, fmt.Errorf(
					"Tunnel protocol %s requires ObfuscatedSSHKey",
					tunnelProtocol)
			}
		}
		if common.TunnelProtocolUsesMeekHTTP(tunnelProtocol) ||
			common.TunnelProtocolUsesMeekHTTPS(tunnelProtocol) {
			if config.MeekCookieEncryptionPrivateKey == "" || config.MeekObfuscatedKey == "" {
				return nil, fmt.Errorf(
					"Tunnel protocol %s requires MeekCookieEncryptionPrivateKey, MeekObfuscatedKey",
					tunnelProtocol)
			}
		}
		if common.TunnelProtocolUsesMeekHTTPS(tunnelProtocol) {
			if config.MeekCertificateCommonName == "" {
				return nil, fmt.Errorf(
					"Tunnel protocol %s requires MeekCertificateCommonName",
					tunnelProtocol)
			}
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
	LogFilename          string
	ServerIPAddress      string
	WebServerPort        int
	EnableSSHAPIRequests bool
	TunnelProtocolPorts  map[string]int
	TrafficRulesFilename string
}

// GenerateConfig creates a new Psiphon server config. It returns JSON
// encoded configs and a client-compatible "server entry" for the server. It
// generates all necessary secrets and key material, which are emitted in
// the config file and server entry as necessary.
// GenerateConfig uses sample values for many fields. The intention is for
// generated configs to be used for testing or as a template for production
// setup, not to generate production-ready configurations.
func GenerateConfig(params *GenerateConfigParams) ([]byte, []byte, []byte, error) {

	// Input validation

	if net.ParseIP(params.ServerIPAddress) == nil {
		return nil, nil, nil, common.ContextError(errors.New("invalid IP address"))
	}

	if len(params.TunnelProtocolPorts) == 0 {
		return nil, nil, nil, common.ContextError(errors.New("no tunnel protocols"))
	}

	usedPort := make(map[int]bool)
	if params.WebServerPort != 0 {
		usedPort[params.WebServerPort] = true
	}

	usingMeek := false

	for protocol, port := range params.TunnelProtocolPorts {

		if !common.Contains(common.SupportedTunnelProtocols, protocol) {
			return nil, nil, nil, common.ContextError(errors.New("invalid tunnel protocol"))
		}

		if usedPort[port] {
			return nil, nil, nil, common.ContextError(errors.New("duplicate listening port"))
		}
		usedPort[port] = true

		if common.TunnelProtocolUsesMeekHTTP(protocol) ||
			common.TunnelProtocolUsesMeekHTTPS(protocol) {
			usingMeek = true
		}
	}

	// Web server config

	var webServerSecret, webServerCertificate,
		webServerPrivateKey, webServerPortForwardAddress string

	if params.WebServerPort != 0 {
		var err error
		webServerSecret, err = common.MakeRandomStringHex(WEB_SERVER_SECRET_BYTE_LENGTH)
		if err != nil {
			return nil, nil, nil, common.ContextError(err)
		}

		webServerCertificate, webServerPrivateKey, err = GenerateWebServerCertificate("")
		if err != nil {
			return nil, nil, nil, common.ContextError(err)
		}

		webServerPortForwardAddress = net.JoinHostPort(
			params.ServerIPAddress, strconv.Itoa(params.WebServerPort))
	}

	// SSH config

	// TODO: use other key types: anti-fingerprint by varying params
	rsaKey, err := rsa.GenerateKey(rand.Reader, SSH_RSA_HOST_KEY_BITS)
	if err != nil {
		return nil, nil, nil, common.ContextError(err)
	}

	sshPrivateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		},
	)

	signer, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		return nil, nil, nil, common.ContextError(err)
	}

	sshPublicKey := signer.PublicKey()

	sshUserNameSuffix, err := common.MakeRandomStringHex(SSH_USERNAME_SUFFIX_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, common.ContextError(err)
	}

	sshUserName := "psiphon_" + sshUserNameSuffix

	sshPassword, err := common.MakeRandomStringHex(SSH_PASSWORD_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, common.ContextError(err)
	}

	// TODO: vary version string for anti-fingerprint
	sshServerVersion := "SSH-2.0-Psiphon"

	// Obfuscated SSH config

	obfuscatedSSHKey, err := common.MakeRandomStringHex(SSH_OBFUSCATED_KEY_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, common.ContextError(err)
	}

	// Meek config

	var meekCookieEncryptionPublicKey, meekCookieEncryptionPrivateKey, meekObfuscatedKey string

	if usingMeek {
		rawMeekCookieEncryptionPublicKey, rawMeekCookieEncryptionPrivateKey, err :=
			box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, common.ContextError(err)
		}

		meekCookieEncryptionPublicKey = base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPublicKey[:])
		meekCookieEncryptionPrivateKey = base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPrivateKey[:])

		meekObfuscatedKey, err = common.MakeRandomStringHex(SSH_OBFUSCATED_KEY_BYTE_LENGTH)
		if err != nil {
			return nil, nil, nil, common.ContextError(err)
		}
	}

	// Other config

	discoveryValueHMACKey, err := common.MakeRandomStringBase64(DISCOVERY_VALUE_KEY_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, common.ContextError(err)
	}

	// Assemble configs and server entry

	// Note: this config is intended for either testing or as an illustrative
	// example or template and is not intended for production deployment.

	config := &Config{
		LogLevel:                       "info",
		LogFilename:                    params.LogFilename,
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
		MeekCertificateCommonName:      "www.example.org",
		MeekProhibitedHeaders:          nil,
		MeekProxyForwardedForHeaders:   []string{"X-Forwarded-For"},
		LoadMonitorPeriodSeconds:       300,
		TrafficRulesFilename:           params.TrafficRulesFilename,
	}

	encodedConfig, err := json.MarshalIndent(config, "\n", "    ")
	if err != nil {
		return nil, nil, nil, common.ContextError(err)
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
		return nil, nil, nil, common.ContextError(err)
	}

	capabilities := []string{}

	if params.EnableSSHAPIRequests {
		capabilities = append(capabilities, common.CAPABILITY_SSH_API_REQUESTS)
	}

	if params.WebServerPort != 0 {
		capabilities = append(capabilities, common.CAPABILITY_UNTUNNELED_WEB_API_REQUESTS)
	}

	for protocol, _ := range params.TunnelProtocolPorts {
		capabilities = append(capabilities, psiphon.GetCapability(protocol))
	}

	sshPort := params.TunnelProtocolPorts["SSH"]
	obfuscatedSSHPort := params.TunnelProtocolPorts["OSSH"]

	// Meek port limitations
	// - fronted meek protocols are hard-wired in the client to be port 443 or 80.
	// - only one other meek port may be specified.
	meekPort := params.TunnelProtocolPorts["UNFRONTED-MEEK-OSSH"]
	if meekPort == 0 {
		meekPort = params.TunnelProtocolPorts["UNFRONTED-MEEK-HTTPS-OSSH"]
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

	serverEntry := &psiphon.ServerEntry{
		IpAddress:                     params.ServerIPAddress,
		WebServerPort:                 serverEntryWebServerPort,
		WebServerSecret:               webServerSecret,
		WebServerCertificate:          strippedWebServerCertificate,
		SshPort:                       sshPort,
		SshUsername:                   sshUserName,
		SshPassword:                   sshPassword,
		SshHostKey:                    base64.RawStdEncoding.EncodeToString(sshPublicKey.Marshal()),
		SshObfuscatedPort:             obfuscatedSSHPort,
		SshObfuscatedKey:              obfuscatedSSHKey,
		Capabilities:                  capabilities,
		Region:                        "US",
		MeekServerPort:                meekPort,
		MeekCookieEncryptionPublicKey: meekCookieEncryptionPublicKey,
		MeekObfuscatedKey:             meekObfuscatedKey,
		MeekFrontingHosts:             []string{params.ServerIPAddress},
		MeekFrontingAddresses:         []string{params.ServerIPAddress},
		MeekFrontingDisableSNI:        false,
	}

	encodedServerEntry, err := psiphon.EncodeServerEntry(serverEntry)
	if err != nil {
		return nil, nil, nil, common.ContextError(err)
	}

	return encodedConfig, encodedTrafficRulesSet, []byte(encodedServerEntry), nil
}
