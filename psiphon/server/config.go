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
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/ssh"
)

const (
	SERVER_CONFIG_FILENAME                = "psiphond.config"
	SERVER_TRAFFIC_RULES_FILENAME         = "psiphond-traffic-rules.config"
	SERVER_ENTRY_FILENAME                 = "server-entry.dat"
	DEFAULT_SERVER_IP_ADDRESS             = "127.0.0.1"
	WEB_SERVER_SECRET_BYTE_LENGTH         = 32
	DISCOVERY_VALUE_KEY_BYTE_LENGTH       = 32
	WEB_SERVER_READ_TIMEOUT               = 10 * time.Second
	WEB_SERVER_WRITE_TIMEOUT              = 10 * time.Second
	SSH_USERNAME_SUFFIX_BYTE_LENGTH       = 8
	SSH_PASSWORD_BYTE_LENGTH              = 32
	SSH_RSA_HOST_KEY_BITS                 = 2048
	SSH_HANDSHAKE_TIMEOUT                 = 30 * time.Second
	SSH_CONNECTION_READ_DEADLINE          = 5 * time.Minute
	SSH_TCP_PORT_FORWARD_DIAL_TIMEOUT     = 30 * time.Second
	SSH_TCP_PORT_FORWARD_COPY_BUFFER_SIZE = 8192
	SSH_OBFUSCATED_KEY_BYTE_LENGTH        = 32
	GEOIP_SESSION_CACHE_TTL               = 60 * time.Minute
)

// Config specifies the configuration and behavior of a Psiphon
// server.
type Config struct {

	// LogLevel specifies the log level. Valid values are:
	// panic, fatal, error, warn, info, debug
	LogLevel string

	// SyslogFacility specifies the syslog facility to log to.
	// When set, the local syslog service is used for message
	// logging.
	// Valid values include: "user", "local0", "local1", etc.
	SyslogFacility string

	// SyslogTag specifies an optional tag for syslog log
	// messages. The default tag is "psiphon-server". The
	// fail2ban logs, if enabled, also use this tag.
	SyslogTag string

	// Fail2BanFormat is a string format specifier for the
	// log message format to use for fail2ban integration for
	// blocking abusive clients by source IP address.
	// When set, logs with this format are made if clients fail
	// to authenticate.
	// The client's IP address is included with the log message.
	// An example format specifier, which should be compatible
	// with default SSH fail2ban configuration, is
	// "Authentication failure for psiphon-client from %s".
	Fail2BanFormat string

	// DiscoveryValueHMACKey is the network-wide secret value
	// used to determine a unique discovery strategy.
	DiscoveryValueHMACKey string

	// GeoIPDatabaseFilename is the path of the GeoIP2/GeoLite2
	// MaxMind database file. when blank, no GeoIP lookups are
	// performed.
	GeoIPDatabaseFilename string

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
	// udpgw protocol.
	UDPInterceptUdpgwServerAddress string

	// DNSServerAddress specifies the network address of a DNS server
	// to which DNS UDP packets will be forwarded to. When set, any
	// tunneled DNS UDP packets will be re-routed to this destination.
	UDPForwardDNSServerAddress string

	// LoadMonitorPeriodSeconds indicates how frequently to log server
	// load information (number of connected clients per tunnel protocol,
	// number of running goroutines, amount of memory allocated, etc.)
	// The default, 0, disables load logging.
	LoadMonitorPeriodSeconds int

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

// UseFail2Ban indicates whether to log client IP addresses, in authentication
// failure cases, to the local syslog service AUTH facility for use by fail2ban.
func (config *Config) UseFail2Ban() bool {
	return config.Fail2BanFormat != ""
}

// LoadConfig loads and validates a JSON encoded server config.
func LoadConfig(configJSON []byte) (*Config, error) {

	var config Config
	err := json.Unmarshal(configJSON, &config)
	if err != nil {
		return nil, psiphon.ContextError(err)
	}

	if config.Fail2BanFormat != "" && strings.Count(config.Fail2BanFormat, "%s") != 1 {
		return nil, errors.New("Fail2BanFormat must have one '%%s' placeholder")
	}

	if config.ServerIPAddress == "" {
		return nil, errors.New("ServerIPAddress is missing from config file")
	}

	if config.WebServerPort > 0 && (config.WebServerSecret == "" || config.WebServerCertificate == "" ||
		config.WebServerPrivateKey == "") {

		return nil, errors.New(
			"Web server requires WebServerSecret, WebServerCertificate, WebServerPrivateKey")
	}

	for tunnelProtocol, _ := range config.TunnelProtocolPorts {
		if psiphon.TunnelProtocolUsesSSH(tunnelProtocol) ||
			psiphon.TunnelProtocolUsesObfuscatedSSH(tunnelProtocol) {
			if config.SSHPrivateKey == "" || config.SSHServerVersion == "" ||
				config.SSHUserName == "" || config.SSHPassword == "" {
				return nil, fmt.Errorf(
					"Tunnel protocol %s requires SSHPrivateKey, SSHServerVersion, SSHUserName, SSHPassword",
					tunnelProtocol)
			}
		}
		if psiphon.TunnelProtocolUsesObfuscatedSSH(tunnelProtocol) {
			if config.ObfuscatedSSHKey == "" {
				return nil, fmt.Errorf(
					"Tunnel protocol %s requires ObfuscatedSSHKey",
					tunnelProtocol)
			}
		}
		if psiphon.TunnelProtocolUsesMeekHTTP(tunnelProtocol) ||
			psiphon.TunnelProtocolUsesMeekHTTPS(tunnelProtocol) {
			if config.MeekCookieEncryptionPrivateKey == "" || config.MeekObfuscatedKey == "" {
				return nil, fmt.Errorf(
					"Tunnel protocol %s requires MeekCookieEncryptionPrivateKey, MeekObfuscatedKey",
					tunnelProtocol)
			}
		}
		if psiphon.TunnelProtocolUsesMeekHTTPS(tunnelProtocol) {
			if config.MeekCertificateCommonName == "" {
				return nil, fmt.Errorf(
					"Tunnel protocol %s requires MeekCertificateCommonName",
					tunnelProtocol)
			}
		}
	}

	validateNetworkAddress := func(address string) error {
		host, port, err := net.SplitHostPort(address)
		if err == nil && net.ParseIP(host) == nil {
			err = errors.New("Host must be an IP address")
		}
		if err == nil {
			_, err = strconv.Atoi(port)
		}
		return err
	}

	if config.UDPForwardDNSServerAddress != "" {
		if err := validateNetworkAddress(config.UDPForwardDNSServerAddress); err != nil {
			return nil, fmt.Errorf("UDPForwardDNSServerAddress is invalid: %s", err)
		}
	}

	if config.UDPInterceptUdpgwServerAddress != "" {
		if err := validateNetworkAddress(config.UDPInterceptUdpgwServerAddress); err != nil {
			return nil, fmt.Errorf("UDPInterceptUdpgwServerAddress is invalid: %s", err)
		}
	}

	return &config, nil
}

// GenerateConfigParams specifies customizations to be applied to
// a generated server config.
type GenerateConfigParams struct {
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
		return nil, nil, nil, psiphon.ContextError(errors.New("invalid IP address"))
	}

	if len(params.TunnelProtocolPorts) == 0 {
		return nil, nil, nil, psiphon.ContextError(errors.New("no tunnel protocols"))
	}

	usedPort := make(map[int]bool)
	if params.WebServerPort != 0 {
		usedPort[params.WebServerPort] = true
	}

	usingMeek := false

	for protocol, port := range params.TunnelProtocolPorts {

		if !psiphon.Contains(psiphon.SupportedTunnelProtocols, protocol) {
			return nil, nil, nil, psiphon.ContextError(errors.New("invalid tunnel protocol"))
		}

		if usedPort[port] {
			return nil, nil, nil, psiphon.ContextError(errors.New("duplicate listening port"))
		}
		usedPort[port] = true

		if psiphon.TunnelProtocolUsesMeekHTTP(protocol) ||
			psiphon.TunnelProtocolUsesMeekHTTPS(protocol) {
			usingMeek = true
		}
	}

	// Web server config

	var webServerSecret, webServerCertificate, webServerPrivateKey string

	if params.WebServerPort != 0 {
		var err error
		webServerSecret, err = psiphon.MakeRandomStringHex(WEB_SERVER_SECRET_BYTE_LENGTH)
		if err != nil {
			return nil, nil, nil, psiphon.ContextError(err)
		}

		webServerCertificate, webServerPrivateKey, err = GenerateWebServerCertificate("")
		if err != nil {
			return nil, nil, nil, psiphon.ContextError(err)
		}
	}

	// SSH config

	// TODO: use other key types: anti-fingerprint by varying params
	rsaKey, err := rsa.GenerateKey(rand.Reader, SSH_RSA_HOST_KEY_BITS)
	if err != nil {
		return nil, nil, nil, psiphon.ContextError(err)
	}

	sshPrivateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		},
	)

	signer, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		return nil, nil, nil, psiphon.ContextError(err)
	}

	sshPublicKey := signer.PublicKey()

	sshUserNameSuffix, err := psiphon.MakeRandomStringHex(SSH_USERNAME_SUFFIX_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, psiphon.ContextError(err)
	}

	sshUserName := "psiphon_" + sshUserNameSuffix

	sshPassword, err := psiphon.MakeRandomStringHex(SSH_PASSWORD_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, psiphon.ContextError(err)
	}

	// TODO: vary version string for anti-fingerprint
	sshServerVersion := "SSH-2.0-Psiphon"

	// Obfuscated SSH config

	obfuscatedSSHKey, err := psiphon.MakeRandomStringHex(SSH_OBFUSCATED_KEY_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, psiphon.ContextError(err)
	}

	// Meek config

	var meekCookieEncryptionPublicKey, meekCookieEncryptionPrivateKey, meekObfuscatedKey string

	if usingMeek {
		rawMeekCookieEncryptionPublicKey, rawMeekCookieEncryptionPrivateKey, err :=
			box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, psiphon.ContextError(err)
		}

		meekCookieEncryptionPublicKey = base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPublicKey[:])
		meekCookieEncryptionPrivateKey = base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPrivateKey[:])

		meekObfuscatedKey, err = psiphon.MakeRandomStringHex(SSH_OBFUSCATED_KEY_BYTE_LENGTH)
		if err != nil {
			return nil, nil, nil, psiphon.ContextError(err)
		}
	}

	// Other config

	discoveryValueHMACKey, err := psiphon.MakeRandomStringBase64(DISCOVERY_VALUE_KEY_BYTE_LENGTH)
	if err != nil {
		return nil, nil, nil, psiphon.ContextError(err)
	}

	// Assemble configs and server entry

	// Note: this config is intended for either testing or as an illustrative
	// example or template and is not intended for production deployment.

	config := &Config{
		LogLevel:                       "info",
		SyslogFacility:                 "user",
		SyslogTag:                      "psiphon-server",
		Fail2BanFormat:                 "Authentication failure for psiphon-client from %s",
		GeoIPDatabaseFilename:          "",
		HostID:                         "example-host-id",
		ServerIPAddress:                params.ServerIPAddress,
		DiscoveryValueHMACKey:          discoveryValueHMACKey,
		WebServerPort:                  params.WebServerPort,
		WebServerSecret:                webServerSecret,
		WebServerCertificate:           webServerCertificate,
		WebServerPrivateKey:            webServerPrivateKey,
		SSHPrivateKey:                  string(sshPrivateKey),
		SSHServerVersion:               sshServerVersion,
		SSHUserName:                    sshUserName,
		SSHPassword:                    sshPassword,
		ObfuscatedSSHKey:               obfuscatedSSHKey,
		TunnelProtocolPorts:            params.TunnelProtocolPorts,
		UDPForwardDNSServerAddress:     "8.8.8.8:53",
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
		return nil, nil, nil, psiphon.ContextError(err)
	}

	trafficRulesSet := &TrafficRulesSet{
		DefaultRules: TrafficRules{
			DefaultLimits: RateLimits{
				DownstreamUnlimitedBytes: 0,
				DownstreamBytesPerSecond: 0,
				UpstreamUnlimitedBytes:   0,
				UpstreamBytesPerSecond:   0,
			},
			IdleTCPPortForwardTimeoutMilliseconds: 30000,
			IdleUDPPortForwardTimeoutMilliseconds: 30000,
			MaxTCPPortForwardCount:                1024,
			MaxUDPPortForwardCount:                32,
			AllowTCPPorts:                         nil,
			AllowUDPPorts:                         nil,
			DenyTCPPorts:                          nil,
			DenyUDPPorts:                          nil,
		},
	}

	encodedTrafficRulesSet, err := json.MarshalIndent(trafficRulesSet, "\n", "    ")
	if err != nil {
		return nil, nil, nil, psiphon.ContextError(err)
	}

	capabilities := []string{}

	if params.EnableSSHAPIRequests {
		capabilities = append(capabilities, psiphon.CAPABILITY_SSH_API_REQUESTS)
	}

	if params.WebServerPort != 0 {
		capabilities = append(capabilities, psiphon.CAPABILITY_UNTUNNELED_WEB_API_REQUESTS)
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
		return nil, nil, nil, psiphon.ContextError(err)
	}

	return encodedConfig, encodedTrafficRulesSet, []byte(encodedServerEntry), nil
}
