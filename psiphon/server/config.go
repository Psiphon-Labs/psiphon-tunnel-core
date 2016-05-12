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
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"golang.org/x/crypto/ssh"
)

const (
	SERVER_CONFIG_FILENAME                 = "psiphon-server.config"
	SERVER_ENTRY_FILENAME                  = "serverEntry.dat"
	DEFAULT_LOG_LEVEL                      = "info"
	DEFAULT_SYSLOG_TAG                     = "psiphon-server"
	DEFAULT_GEO_IP_DATABASE_FILENAME       = "GeoLite2-City.mmdb"
	DEFAULT_SERVER_IP_ADDRESS              = "127.0.0.1"
	WEB_SERVER_SECRET_BYTE_LENGTH          = 32
	WEB_SERVER_CERTIFICATE_RSA_KEY_BITS    = 2048
	WEB_SERVER_CERTIFICATE_VALIDITY_PERIOD = 10 * 365 * 24 * time.Hour // approx. 10 years
	DEFAULT_WEB_SERVER_PORT                = 8000
	WEB_SERVER_READ_TIMEOUT                = 10 * time.Second
	WEB_SERVER_WRITE_TIMEOUT               = 10 * time.Second
	SSH_USERNAME_SUFFIX_BYTE_LENGTH        = 8
	SSH_PASSWORD_BYTE_LENGTH               = 32
	SSH_RSA_HOST_KEY_BITS                  = 2048
	DEFAULT_SSH_SERVER_PORT                = 2222
	SSH_HANDSHAKE_TIMEOUT                  = 30 * time.Second
	SSH_CONNECTION_READ_DEADLINE           = 5 * time.Minute
	SSH_OBFUSCATED_KEY_BYTE_LENGTH         = 32
	DEFAULT_OBFUSCATED_SSH_SERVER_PORT     = 3333
	REDIS_POOL_MAX_IDLE                    = 50
	REDIS_POOL_MAX_ACTIVE                  = 1000
	REDIS_POOL_IDLE_TIMEOUT                = 5 * time.Minute
)

// TODO: break config into sections (sub-structs)

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
	// When set, logs with this format are made to the AUTH
	// facility with INFO severity in the local syslog server
	// if clients fail to authenticate.
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

	// SSHServerPort is the listening port of the SSH server.
	// When <= 0, no SSH server component is run.
	SSHServerPort int

	// SSHPrivateKey is the SSH host key. The same key is used for
	// both the SSH and Obfuscated SSH servers.
	SSHPrivateKey string

	// SSHServerVersion is the server version presented in the
	// identification string. The same value is used for both SSH
	// and Obfuscated SSH servers.
	SSHServerVersion string

	// SSHUserName is the SSH user name to be presented by the
	// the tunnel-core client. The same value is used for both SSH
	// and Obfuscated SSH servers.
	SSHUserName string

	// SSHPassword is the SSH password to be presented by the
	// the tunnel-core client. The same value is used for both SSH
	// and Obfuscated SSH servers.
	SSHPassword string

	// ObfuscatedSSHServerPort is the listening port of the Obfuscated SSH server.
	// When <= 0, no Obfuscated SSH server component is run.
	ObfuscatedSSHServerPort int

	// ObfuscatedSSHKey is the secret key for use in the Obfuscated
	// SSH protocol.
	ObfuscatedSSHKey string

	// RedisServerAddress is the TCP address of a redis server. When
	// set, redis is used to store per-session GeoIP information.
	RedisServerAddress string

	// DefaultTrafficRules specifies the traffic rules to be used when
	// no regional-specific rules are set.
	DefaultTrafficRules TrafficRules

	// RegionalTrafficRules specifies the traffic rules for particular
	// client regions (countries) as determined by GeoIP lookup of the
	// client IP address. The key for each regional traffic rule entry
	// is one or more space delimited ISO 3166-1 alpha-2 country codes.
	RegionalTrafficRules map[string]TrafficRules

	// DNSServerAddress specifies the network address of a DNS server
	// to which DNS UDP packets will be forwarded to. When set, any
	// tunneled DNS UDP packets will be re-routed to this destination.
	DNSServerAddress string

	// UdpgwServerAddress specifies the network address of a udpgw
	// server which clients may be port forwarding to. When specified,
	// these TCP port forwards are intercepted and handled directly
	// by this server, which parses the SSH channel using the udpgw
	// protocol.
	UdpgwServerAddress string
}

// TrafficRules specify the limits placed on client traffic.
type TrafficRules struct {

	// LimitDownstreamBytesPerSecond specifies a rate limit for
	// downstream data transfer between a single client and the
	// server.
	// The default, 0, is no rate limit.
	LimitDownstreamBytesPerSecond int

	// LimitUpstreamBytesPerSecond specifies a rate limit for
	// upstream data transfer between a single client and the
	// server.
	// The default, 0, is no rate limit.
	LimitUpstreamBytesPerSecond int

	// IdlePortForwardTimeoutMilliseconds is the timeout period
	// after which idle (no bytes flowing in either direction)
	// SSH client port forwards are preemptively closed.
	// The default, 0, is no idle timeout.
	IdlePortForwardTimeoutMilliseconds int

	// MaxTCPPortForwardCount is the maximum number of TCP port
	// forwards each client may have open concurrently.
	// The default, 0, is no maximum.
	MaxTCPPortForwardCount int

	// MaxUDPPortForwardCount is the maximum number of UDP port
	// forwards each client may have open concurrently.
	// The default, 0, is no maximum.
	MaxUDPPortForwardCount int

	// AllowTCPPorts specifies a whitelist of TCP ports that
	// are permitted for port forwarding. When set, only ports
	// in the list are accessible to clients.
	AllowTCPPorts []int

	// AllowUDPPorts specifies a whitelist of UDP ports that
	// are permitted for port forwarding. When set, only ports
	// in the list are accessible to clients.
	AllowUDPPorts []int

	// DenyTCPPorts specifies a blacklist of TCP ports that
	// are not permitted for port forwarding. When set, the
	// ports in the list are inaccessible to clients.
	DenyTCPPorts []int

	// DenyUDPPorts specifies a blacklist of UDP ports that
	// are not permitted for port forwarding. When set, the
	// ports in the list are inaccessible to clients.
	DenyUDPPorts []int
}

// RunWebServer indicates whether to run a web server component.
func (config *Config) RunWebServer() bool {
	return config.WebServerPort > 0
}

// RunSSHServer indicates whether to run an SSH server component.
func (config *Config) RunSSHServer() bool {
	return config.SSHServerPort > 0
}

// RunObfuscatedSSHServer indicates whether to run an Obfuscated SSH server component.
func (config *Config) RunObfuscatedSSHServer() bool {
	return config.ObfuscatedSSHServerPort > 0
}

// UseRedis indicates whether to store per-session GeoIP information in
// redis. This is for integration with the legacy psi_web component.
func (config *Config) UseRedis() bool {
	return config.RedisServerAddress != ""
}

// UseFail2Ban indicates whether to log client IP addresses, in authentication
// failure cases, to the local syslog service AUTH facility for use by fail2ban.
func (config *Config) UseFail2Ban() bool {
	return config.Fail2BanFormat != ""
}

// GetTrafficRules looks up the traffic rules for the specified country. If there
// are no RegionalTrafficRules for the country, DefaultTrafficRules are returned.
func (config *Config) GetTrafficRules(targetCountryCode string) TrafficRules {
	// TODO: faster lookup?
	for countryCodes, trafficRules := range config.RegionalTrafficRules {
		for _, countryCode := range strings.Split(countryCodes, " ") {
			if countryCode == targetCountryCode {
				return trafficRules
			}
		}
	}
	return config.DefaultTrafficRules
}

// LoadConfig loads and validates a JSON encoded server config. If more than one
// JSON config is specified, then all are loaded and values are merged together,
// in order. Multiple configs allows for use cases like storing static, server-specific
// values in a base config while also deploying network-wide throttling settings
// in a secondary file that can be paved over on all server hosts.
func LoadConfig(configJSONs [][]byte) (*Config, error) {

	// Note: default values are set in GenerateConfig
	var config Config

	for _, configJSON := range configJSONs {
		err := json.Unmarshal(configJSON, &config)
		if err != nil {
			return nil, psiphon.ContextError(err)
		}
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

	if config.SSHServerPort > 0 && (config.SSHPrivateKey == "" || config.SSHServerVersion == "" ||
		config.SSHUserName == "" || config.SSHPassword == "") {

		return nil, errors.New(
			"SSH server requires SSHPrivateKey, SSHServerVersion, SSHUserName, SSHPassword")
	}

	if config.ObfuscatedSSHServerPort > 0 && (config.SSHPrivateKey == "" || config.SSHServerVersion == "" ||
		config.SSHUserName == "" || config.SSHPassword == "" || config.ObfuscatedSSHKey == "") {

		return nil, errors.New(
			"Obfuscated SSH server requires SSHPrivateKey, SSHServerVersion, SSHUserName, SSHPassword, ObfuscatedSSHKey")
	}

	validateNetworkAddress := func(address string) error {
		_, portStr, err := net.SplitHostPort(config.DNSServerAddress)
		if err == nil {
			_, err = strconv.Atoi(portStr)
		}
		return err
	}

	if config.DNSServerAddress != "" {
		if err := validateNetworkAddress(config.DNSServerAddress); err != nil {
			return nil, fmt.Errorf("DNSServerAddress is invalid: %s", err)
		}
	}

	if config.UdpgwServerAddress != "" {
		if err := validateNetworkAddress(config.UdpgwServerAddress); err != nil {
			return nil, fmt.Errorf("UdpgwServerAddress is invalid: %s", err)
		}
	}

	return &config, nil
}

// GenerateConfigParams specifies customizations to be applied to
// a generated server config.
type GenerateConfigParams struct {

	// ServerIPAddress is the public IP address of the server.
	ServerIPAddress string

	// WebServerPort is the listening port of the web server.
	// When <= 0, no web server component is run.
	WebServerPort int

	// SSHServerPort is the listening port of the SSH server.
	// When <= 0, no SSH server component is run.
	SSHServerPort int

	// ObfuscatedSSHServerPort is the listening port of the Obfuscated SSH server.
	// When <= 0, no Obfuscated SSH server component is run.
	ObfuscatedSSHServerPort int
}

// GenerateConfig create a new Psiphon server config. It returns a JSON
// encoded config and a client-compatible "server entry" for the server. It
// generates all necessary secrets and key material, which are emitted in
// the config file and server entry as necessary.
func GenerateConfig(params *GenerateConfigParams) ([]byte, []byte, error) {

	// TODO: support disabling web server or a subset of protocols

	serverIPaddress := params.ServerIPAddress
	if serverIPaddress == "" {
		serverIPaddress = DEFAULT_SERVER_IP_ADDRESS
	}

	// Web server config

	webServerPort := params.WebServerPort
	if webServerPort == 0 {
		webServerPort = DEFAULT_WEB_SERVER_PORT
	}

	webServerSecret, err := psiphon.MakeRandomString(WEB_SERVER_SECRET_BYTE_LENGTH)
	if err != nil {
		return nil, nil, psiphon.ContextError(err)
	}

	webServerCertificate, webServerPrivateKey, err := generateWebServerCertificate()
	if err != nil {
		return nil, nil, psiphon.ContextError(err)
	}

	// SSH config

	sshServerPort := params.SSHServerPort
	if sshServerPort == 0 {
		sshServerPort = DEFAULT_SSH_SERVER_PORT
	}

	// TODO: use other key types: anti-fingerprint by varying params

	rsaKey, err := rsa.GenerateKey(rand.Reader, SSH_RSA_HOST_KEY_BITS)
	if err != nil {
		return nil, nil, psiphon.ContextError(err)
	}

	sshPrivateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		},
	)

	signer, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		return nil, nil, psiphon.ContextError(err)
	}

	sshPublicKey := signer.PublicKey()

	sshUserNameSuffix, err := psiphon.MakeRandomString(SSH_USERNAME_SUFFIX_BYTE_LENGTH)
	if err != nil {
		return nil, nil, psiphon.ContextError(err)
	}

	sshUserName := "psiphon_" + sshUserNameSuffix

	sshPassword, err := psiphon.MakeRandomString(SSH_PASSWORD_BYTE_LENGTH)
	if err != nil {
		return nil, nil, psiphon.ContextError(err)
	}

	// TODO: vary version string for anti-fingerprint
	sshServerVersion := "SSH-2.0-Psiphon"

	// Obfuscated SSH config

	obfuscatedSSHServerPort := params.ObfuscatedSSHServerPort
	if obfuscatedSSHServerPort == 0 {
		obfuscatedSSHServerPort = DEFAULT_OBFUSCATED_SSH_SERVER_PORT
	}

	obfuscatedSSHKey, err := psiphon.MakeRandomString(SSH_OBFUSCATED_KEY_BYTE_LENGTH)
	if err != nil {
		return nil, nil, psiphon.ContextError(err)
	}

	// Assemble config and server entry

	config := &Config{
		LogLevel:                DEFAULT_LOG_LEVEL,
		SyslogFacility:          "",
		SyslogTag:               DEFAULT_SYSLOG_TAG,
		Fail2BanFormat:          "",
		DiscoveryValueHMACKey:   "",
		GeoIPDatabaseFilename:   DEFAULT_GEO_IP_DATABASE_FILENAME,
		ServerIPAddress:         serverIPaddress,
		WebServerPort:           webServerPort,
		WebServerSecret:         webServerSecret,
		WebServerCertificate:    webServerCertificate,
		WebServerPrivateKey:     webServerPrivateKey,
		SSHPrivateKey:           string(sshPrivateKey),
		SSHServerVersion:        sshServerVersion,
		SSHUserName:             sshUserName,
		SSHPassword:             sshPassword,
		SSHServerPort:           sshServerPort,
		ObfuscatedSSHKey:        obfuscatedSSHKey,
		ObfuscatedSSHServerPort: obfuscatedSSHServerPort,
		RedisServerAddress:      "",
	}

	encodedConfig, err := json.MarshalIndent(config, "\n", "    ")
	if err != nil {
		return nil, nil, psiphon.ContextError(err)
	}

	// Server entry format omits the BEGIN/END lines and newlines
	lines := strings.Split(webServerCertificate, "\n")
	strippedWebServerCertificate := strings.Join(lines[1:len(lines)-2], "")

	capabilities := []string{
		psiphon.GetCapability(psiphon.TUNNEL_PROTOCOL_SSH),
		psiphon.GetCapability(psiphon.TUNNEL_PROTOCOL_OBFUSCATED_SSH),
	}

	serverEntry := &psiphon.ServerEntry{
		IpAddress:            serverIPaddress,
		WebServerPort:        fmt.Sprintf("%d", webServerPort),
		WebServerSecret:      webServerSecret,
		WebServerCertificate: strippedWebServerCertificate,
		SshPort:              sshServerPort,
		SshUsername:          sshUserName,
		SshPassword:          sshPassword,
		SshHostKey:           base64.RawStdEncoding.EncodeToString(sshPublicKey.Marshal()),
		SshObfuscatedPort:    obfuscatedSSHServerPort,
		SshObfuscatedKey:     obfuscatedSSHKey,
		Capabilities:         capabilities,
		Region:               "US",
	}

	encodedServerEntry, err := psiphon.EncodeServerEntry(serverEntry)
	if err != nil {
		return nil, nil, psiphon.ContextError(err)
	}

	return encodedConfig, []byte(encodedServerEntry), nil
}

func generateWebServerCertificate() (string, string, error) {

	// Based on https://golang.org/src/crypto/tls/generate_cert.go

	// TODO: use other key types: anti-fingerprint by varying params

	rsaKey, err := rsa.GenerateKey(rand.Reader, WEB_SERVER_CERTIFICATE_RSA_KEY_BITS)
	if err != nil {
		return "", "", psiphon.ContextError(err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(WEB_SERVER_CERTIFICATE_VALIDITY_PERIOD)

	// TODO: psi_ops_install sets serial number to 0?
	// TODO: psi_ops_install sets RSA exponent to 3, digest type to 'sha1', and version to 2?

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", psiphon.ContextError(err)
	}

	template := x509.Certificate{

		// TODO: psi_ops_install leaves subject blank?
		/*
			Subject: pkix.Name{
				Organization: []string{""},
			},
			IPAddresses: ...
		*/

		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}

	derCert, err := x509.CreateCertificate(rand.Reader, &template, &template, rsaKey.Public(), rsaKey)
	if err != nil {
		return "", "", psiphon.ContextError(err)
	}

	webServerCertificate := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derCert,
		},
	)

	webServerPrivateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		},
	)

	return string(webServerCertificate), string(webServerPrivateKey), nil
}
