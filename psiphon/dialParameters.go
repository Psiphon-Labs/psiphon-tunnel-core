/*
 * Copyright (c) 2018, Psiphon Inc.
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
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	regen "github.com/zach-klippenstein/goregen"
)

// DialParameters represents a selected protocol and all the related selected
// protocol attributes, many chosen at random, for a tunnel dial attempt.
//
// DialParameters is used:
// - to configure dialers
// - as a persistent record to store successful dial parameters for replay
// - to report dial stats in notices and Psiphon API calls.
//
// MeekResolvedIPAddress is set asynchronously, as it is not known until the
// dial process has begun. The atomic.Value will contain a string, initialized
// to "", and set to the resolved IP address once that part of the dial
// process has completed.
//
// DialParameters is not safe for concurrent use.
type DialParameters struct {
	ServerEntry     *protocol.ServerEntry `json:"-"`
	NetworkID       string                `json:"-"`
	IsReplay        bool                  `json:"-"`
	CandidateNumber int                   `json:"-"`

	LastUsedTimestamp       time.Time
	LastUsedConfigStateHash []byte

	TunnelProtocol string

	DirectDialAddress              string
	DialPortNumber                 string
	UpstreamProxyType              string   `json:"-"`
	UpstreamProxyCustomHeaderNames []string `json:"-"`

	SelectedSSHClientVersion bool
	SSHClientVersion         string
	SSHKEXSeed               *prng.Seed

	ObfuscatorPaddingSeed *prng.Seed

	FragmentorSeed *prng.Seed

	MeekFrontingDialAddress   string
	MeekFrontingHost          string
	MeekDialAddress           string
	MeekTransformedHostName   bool
	MeekSNIServerName         string
	MeekHostHeader            string
	MeekObfuscatorPaddingSeed *prng.Seed
	MeekResolvedIPAddress     atomic.Value `json:"-"`

	SelectedUserAgent bool
	UserAgent         string

	SelectedTLSProfile       bool
	TLSProfile               string
	RandomizedTLSProfileSeed *prng.Seed

	QUICVersion               string
	QUICDialSNIAddress        string
	ObfuscatedQUICPaddingSeed *prng.Seed

	LivenessTestSeed *prng.Seed

	APIRequestPaddingSeed *prng.Seed

	DialConnMetrics          common.MetricsSource `json:"-"`
	ObfuscatedSSHConnMetrics common.MetricsSource `json:"-"`

	DialDuration time.Duration `json:"-"`

	dialConfig *DialConfig `json:"-"`
	meekConfig *MeekConfig `json:"-"`
}

// MakeDialParameters creates a new DialParameters for the candidate server
// entry, including selecting a protocol and all the various protocol
// attributes. The input selectProtocol is used to comply with any active
// protocol selection constraints.
//
// When stored dial parameters are available and may be used,
// MakeDialParameters may replay previous dial parameters in an effort to
// leverage "known working" values instead of always chosing at random from a
// large space.
//
// MakeDialParameters will return nil/nil in cases where the candidate server
// entry should be skipped.
//
// To support replay, the caller must call DialParameters.Succeeded when a
// successful tunnel is established with the returned DialParameters; and must
// call DialParameters.Failed when a tunnel dial or activation fails, except
// when establishment is cancelled.
func MakeDialParameters(
	config *Config,
	canReplay func(serverEntry *protocol.ServerEntry, replayProtocol string) bool,
	selectProtocol func(serverEntry *protocol.ServerEntry) (string, bool),
	serverEntry *protocol.ServerEntry,
	isTactics bool,
	candidateNumber int) (*DialParameters, error) {

	networkID := config.GetNetworkID()

	p := config.clientParameters.Get()

	ttl := p.Duration(parameters.ReplayDialParametersTTL)
	replaySSH := p.Bool(parameters.ReplaySSH)
	replayObfuscatorPadding := p.Bool(parameters.ReplayObfuscatorPadding)
	replayFragmentor := p.Bool(parameters.ReplayFragmentor)
	replayTLSProfile := p.Bool(parameters.ReplayTLSProfile)
	replayRandomizedTLSProfile := p.Bool(parameters.ReplayRandomizedTLSProfile)
	replayFronting := p.Bool(parameters.ReplayFronting)
	replayHostname := p.Bool(parameters.ReplayHostname)
	replayQUICVersion := p.Bool(parameters.ReplayQUICVersion)
	replayObfuscatedQUIC := p.Bool(parameters.ReplayObfuscatedQUIC)
	replayLivenessTest := p.Bool(parameters.ReplayLivenessTest)
	replayUserAgent := p.Bool(parameters.ReplayUserAgent)
	replayAPIRequestPadding := p.Bool(parameters.ReplayAPIRequestPadding)

	// Check for existing dial parameters for this server/network ID.

	dialParams, err := GetDialParameters(serverEntry.IpAddress, networkID)
	if err != nil {
		NoticeAlert("GetDialParameters failed: %s", err)
		dialParams = nil
		// Proceed, without existing dial parameters.
	}

	// Check if replay is permitted:
	// - TTL must be > 0 and existing dial parameters must not have expired
	//   as indicated by LastUsedTimestamp + TTL.
	// - Config/tactics/server entry values must be unchanged from when
	//   previous dial parameters were established.
	// - The protocol selection constraints must permit replay, as indicated
	//   by canReplay.
	//
	// When existing dial parameters don't meet these conditions, dialParams
	// is reset to nil and new dial parameters will be generated.

	var currentTimestamp time.Time
	var configStateHash []byte

	// When TTL is 0, replay is disabled; the timestamp remains 0 and the
	// output DialParameters will not be stored by Success.

	if ttl > 0 {
		currentTimestamp = time.Now()
		configStateHash = getConfigStateHash(config, p, serverEntry)
	}

	if dialParams != nil &&
		(ttl <= 0 ||
			dialParams.LastUsedTimestamp.Before(currentTimestamp.Add(-ttl)) ||
			bytes.Compare(dialParams.LastUsedConfigStateHash, configStateHash) != 0) {

		// In these cases, existing dial parameters are expired or no longer
		// match the config state and so are cleared to avoid rechecking them.

		err = DeleteDialParameters(serverEntry.IpAddress, networkID)
		if err != nil {
			NoticeAlert("DeleteDialParameters failed: %s", err)
		}
		dialParams = nil
	}

	if dialParams != nil {
		if !canReplay(serverEntry, dialParams.TunnelProtocol) {

			// In this ephemeral case, existing dial parameters may still be
			// valid and used in future establishment phases, and so are
			// retained.

			dialParams = nil
		}
	}

	isReplay := (dialParams != nil)

	if !isReplay {
		dialParams = &DialParameters{}
	}

	dialParams.ServerEntry = serverEntry
	dialParams.NetworkID = networkID
	dialParams.IsReplay = isReplay
	dialParams.CandidateNumber = candidateNumber

	// Even when replaying, LastUsedTimestamp is updated to extend the TTL of
	// replayed dial parameters which will be updated in the datastore upon
	// success.

	dialParams.LastUsedTimestamp = currentTimestamp
	dialParams.LastUsedConfigStateHash = configStateHash

	// Initialize dial parameters.
	//
	// When not replaying, all required parameters are initialized. When
	// replaying, existing parameters are retaing, subject to the replay-X
	// tactics flags.

	if !isReplay {

		// TODO: should there be a pre-check of selectProtocol before incurring
		// overhead of unmarshaling dial parameters? In may be that a server entry
		// is fully incapable of satisfying the current protocol selection
		// constraints.

		selectedProtocol, ok := selectProtocol(serverEntry)
		if !ok {
			return nil, nil
		}

		dialParams.TunnelProtocol = selectedProtocol
	}

	if !isReplay || !replaySSH {
		dialParams.SelectedSSHClientVersion = true
		dialParams.SSHClientVersion = pickSSHClientVersion()
		dialParams.SSHKEXSeed, err = prng.NewSeed()
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	if !isReplay || !replayObfuscatorPadding {
		dialParams.ObfuscatorPaddingSeed, err = prng.NewSeed()
		if err != nil {
			return nil, common.ContextError(err)
		}
		if protocol.TunnelProtocolUsesMeek(dialParams.TunnelProtocol) {
			dialParams.MeekObfuscatorPaddingSeed, err = prng.NewSeed()
			if err != nil {
				return nil, common.ContextError(err)
			}
		}
	}

	if !isReplay || !replayFragmentor {
		dialParams.FragmentorSeed, err = prng.NewSeed()
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	if (!isReplay || !replayTLSProfile) &&
		protocol.TunnelProtocolUsesMeekHTTPS(dialParams.TunnelProtocol) {

		dialParams.SelectedTLSProfile = true
		dialParams.TLSProfile = SelectTLSProfile(p)
	}

	if (!isReplay || !replayRandomizedTLSProfile) &&
		protocol.TunnelProtocolUsesMeekHTTPS(dialParams.TunnelProtocol) &&
		protocol.TLSProfileIsRandomized(dialParams.TLSProfile) {

		dialParams.RandomizedTLSProfileSeed, err = prng.NewSeed()
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	if (!isReplay || !replayFronting) &&
		protocol.TunnelProtocolUsesFrontedMeek(dialParams.TunnelProtocol) {

		dialParams.MeekFrontingDialAddress, dialParams.MeekFrontingHost, err =
			selectFrontingParameters(serverEntry)
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	if !isReplay || !replayHostname {

		if protocol.TunnelProtocolUsesQUIC(dialParams.TunnelProtocol) {

			dialParams.QUICDialSNIAddress = fmt.Sprintf("%s:%d", common.GenerateHostName(), serverEntry.SshObfuscatedQUICPort)

		} else if protocol.TunnelProtocolUsesMeekHTTPS(dialParams.TunnelProtocol) {

			dialParams.MeekSNIServerName = ""
			if p.WeightedCoinFlip(parameters.TransformHostNameProbability) {
				dialParams.MeekSNIServerName = common.GenerateHostName()
				dialParams.MeekTransformedHostName = true
			}

		} else if protocol.TunnelProtocolUsesMeekHTTP(dialParams.TunnelProtocol) {

			dialParams.MeekHostHeader = ""
			hostname := serverEntry.IpAddress
			if p.WeightedCoinFlip(parameters.TransformHostNameProbability) {
				hostname = common.GenerateHostName()
				dialParams.MeekTransformedHostName = true
			}
			if serverEntry.MeekServerPort == 80 {
				dialParams.MeekHostHeader = hostname
			} else {
				dialParams.MeekHostHeader = fmt.Sprintf("%s:%d", hostname, serverEntry.MeekServerPort)
			}
		}
	}

	if (!isReplay || !replayQUICVersion) &&
		protocol.TunnelProtocolUsesQUIC(dialParams.TunnelProtocol) {

		dialParams.QUICVersion = selectQUICVersion(p)
	}

	if (!isReplay || !replayObfuscatedQUIC) &&
		protocol.QUICVersionIsObfuscated(dialParams.QUICVersion) {

		dialParams.ObfuscatedQUICPaddingSeed, err = prng.NewSeed()
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	if !isReplay || !replayLivenessTest {

		// TODO: initialize only when LivenessTestMaxUp/DownstreamBytes > 0?
		dialParams.LivenessTestSeed, err = prng.NewSeed()
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	if !isReplay || !replayAPIRequestPadding {
		dialParams.APIRequestPaddingSeed, err = prng.NewSeed()
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	// Set dial address fields. This portion of configuration is
	// deterministic, given the parameters established or replayed so far.

	switch dialParams.TunnelProtocol {

	case protocol.TUNNEL_PROTOCOL_SSH:
		dialParams.DirectDialAddress = fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.SshPort)

	case protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH:
		dialParams.DirectDialAddress = fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.SshObfuscatedPort)

	case protocol.TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH:
		dialParams.DirectDialAddress = fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.SshObfuscatedTapdancePort)

	case protocol.TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH:
		dialParams.DirectDialAddress = fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.SshObfuscatedQUICPort)

	case protocol.TUNNEL_PROTOCOL_MARIONETTE_OBFUSCATED_SSH:
		// Note: port comes from marionnete "format"
		dialParams.DirectDialAddress = serverEntry.IpAddress

	case protocol.TUNNEL_PROTOCOL_FRONTED_MEEK:
		dialParams.MeekDialAddress = fmt.Sprintf("%s:443", dialParams.MeekFrontingDialAddress)
		dialParams.MeekHostHeader = dialParams.MeekFrontingHost
		if serverEntry.MeekFrontingDisableSNI {
			dialParams.MeekSNIServerName = ""
		} else if !dialParams.MeekTransformedHostName {
			dialParams.MeekSNIServerName = dialParams.MeekFrontingDialAddress
		}

	case protocol.TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP:
		dialParams.MeekDialAddress = fmt.Sprintf("%s:80", dialParams.MeekFrontingDialAddress)
		dialParams.MeekHostHeader = dialParams.MeekFrontingHost

	case protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK:
		dialParams.MeekDialAddress = fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.MeekServerPort)
		if !dialParams.MeekTransformedHostName {
			if serverEntry.MeekServerPort == 80 {
				dialParams.MeekHostHeader = serverEntry.IpAddress
			} else {
				dialParams.MeekHostHeader = dialParams.MeekDialAddress
			}
		}

	case protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
		protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET:

		dialParams.MeekDialAddress = fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.MeekServerPort)
		if !dialParams.MeekTransformedHostName {
			// Note: IP address in SNI field will be omitted.
			dialParams.MeekSNIServerName = serverEntry.IpAddress
		}
		if serverEntry.MeekServerPort == 443 {
			dialParams.MeekHostHeader = serverEntry.IpAddress
		} else {
			dialParams.MeekHostHeader = dialParams.MeekDialAddress
		}

	default:
		return nil, common.ContextError(
			fmt.Errorf("unknown tunnel protocol: %s", dialParams.TunnelProtocol))

	}

	if protocol.TunnelProtocolUsesMeek(dialParams.TunnelProtocol) {

		host, port, _ := net.SplitHostPort(dialParams.MeekDialAddress)

		if p.Bool(parameters.MeekDialDomainsOnly) {
			if net.ParseIP(host) != nil {
				// No error, as this is a "not supported" case.
				return nil, nil
			}
		}

		dialParams.DialPortNumber = port

		// The underlying TLS will automatically disable SNI for IP address server name
		// values; we have this explicit check here so we record the correct value for stats.
		if net.ParseIP(dialParams.MeekSNIServerName) != nil {
			dialParams.MeekSNIServerName = ""
		}

	} else {

		_, dialParams.DialPortNumber, _ = net.SplitHostPort(dialParams.DirectDialAddress)
	}

	// Initialize/replay User-Agent header for HTTP upstream proxy and meek protocols.

	if config.UseUpstreamProxy() {
		// Note: UpstreamProxyURL will be validated in the dial
		proxyURL, err := url.Parse(config.UpstreamProxyURL)
		if err == nil {
			dialParams.UpstreamProxyType = proxyURL.Scheme
		}
	}

	dialCustomHeaders := makeDialCustomHeaders(config, p)

	if protocol.TunnelProtocolUsesMeek(dialParams.TunnelProtocol) || dialParams.UpstreamProxyType == "http" {

		if !isReplay || !replayUserAgent {
			dialParams.SelectedUserAgent, dialParams.UserAgent = PickUserAgentIfUnset(p, dialCustomHeaders)
		}

		if dialParams.SelectedUserAgent {
			dialCustomHeaders.Set("User-Agent", dialParams.UserAgent)
		}

	}

	// UpstreamProxyCustomHeaderNames is a reported metric. Just the names and
	// not the values are reported, in case the values are identifying.

	if len(config.CustomHeaders) > 0 {
		dialParams.UpstreamProxyCustomHeaderNames = make([]string, 0)
		for name := range dialCustomHeaders {
			if name == "User-Agent" && dialParams.SelectedUserAgent {
				continue
			}
			dialParams.UpstreamProxyCustomHeaderNames = append(dialParams.UpstreamProxyCustomHeaderNames, name)
		}
	}

	// Initialize Dial/MeekConfigs to be passed to the corresponding dialers.

	dialParams.dialConfig = &DialConfig{
		UpstreamProxyURL:              config.UpstreamProxyURL,
		CustomHeaders:                 dialCustomHeaders,
		DeviceBinder:                  config.deviceBinder,
		DnsServerGetter:               config.DnsServerGetter,
		IPv6Synthesizer:               config.IPv6Synthesizer,
		TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
		FragmentorConfig:              fragmentor.NewUpstreamConfig(p, dialParams.TunnelProtocol, dialParams.FragmentorSeed),
	}

	// Unconditionally initialize MeekResolvedIPAddress, so a valid string can
	// always be read.
	dialParams.MeekResolvedIPAddress.Store("")

	if protocol.TunnelProtocolUsesMeek(dialParams.TunnelProtocol) {

		dialParams.meekConfig = &MeekConfig{
			ClientParameters:              config.clientParameters,
			DialAddress:                   dialParams.MeekDialAddress,
			UseHTTPS:                      protocol.TunnelProtocolUsesMeekHTTPS(dialParams.TunnelProtocol),
			TLSProfile:                    dialParams.TLSProfile,
			RandomizedTLSProfileSeed:      dialParams.RandomizedTLSProfileSeed,
			UseObfuscatedSessionTickets:   dialParams.TunnelProtocol == protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET,
			SNIServerName:                 dialParams.MeekSNIServerName,
			HostHeader:                    dialParams.MeekHostHeader,
			TransformedHostName:           dialParams.MeekTransformedHostName,
			ClientTunnelProtocol:          dialParams.TunnelProtocol,
			MeekCookieEncryptionPublicKey: serverEntry.MeekCookieEncryptionPublicKey,
			MeekObfuscatedKey:             serverEntry.MeekObfuscatedKey,
			MeekObfuscatorPaddingSeed:     dialParams.MeekObfuscatorPaddingSeed,
		}

		// Use an asynchronous callback to record the resolved IP address when
		// dialing a domain name. Note that DialMeek doesn't immediately
		// establish any HTTP connections, so the resolved IP address won't be
		// reported in all cases until after SSH traffic is relayed or a
		// endpoint request is made over the meek connection.
		dialParams.dialConfig.ResolvedIPCallback = func(IPAddress string) {
			dialParams.MeekResolvedIPAddress.Store(IPAddress)
		}

		if isTactics {
			dialParams.meekConfig.RoundTripperOnly = true
		}
	}

	return dialParams, nil
}

func (dialParams *DialParameters) GetDialConfig() *DialConfig {
	return dialParams.dialConfig
}

func (dialParams *DialParameters) GetMeekConfig() *MeekConfig {
	return dialParams.meekConfig
}

func (dialParams *DialParameters) Succeeded() {

	// When TTL is 0, don't store dial parameters.
	if dialParams.LastUsedTimestamp.IsZero() {
		return
	}

	NoticeInfo("Set dial parameters for %s", dialParams.ServerEntry.IpAddress)
	err := SetDialParameters(dialParams.ServerEntry.IpAddress, dialParams.NetworkID, dialParams)
	if err != nil {
		NoticeAlert("SetDialParameters failed: %s", err)
	}
}

func (dialParams *DialParameters) Failed() {

	// When a tunnel fails, and the dial is a replay, clear the stored dial
	// parameters which are now presumed to be blocked, impaired or otherwise
	// no longer effective.
	//
	// It may be the case that a dial is not using stored dial parameters, and
	// in this case we retain those dial parameters since they were not
	// exercised and may still be efective.

	if dialParams.IsReplay {
		NoticeInfo("Delete dial parameters for %s", dialParams.ServerEntry.IpAddress)
		err := DeleteDialParameters(dialParams.ServerEntry.IpAddress, dialParams.NetworkID)
		if err != nil {
			NoticeAlert("DeleteDialParameters failed: %s", err)
		}
	}
}

func getConfigStateHash(
	config *Config,
	p *parameters.ClientParametersSnapshot,
	serverEntry *protocol.ServerEntry) []byte {

	// The config state hash should reflect config, tactics, and server entry
	// settings that impact the dial parameters. The hash should change if any
	// of these input values change in a way that invalidates any stored dial
	// parameters.

	// MD5 hash is used solely as a data checksum and not for any security purpose.
	hash := md5.New()

	hash.Write([]byte(p.Tag()))

	// TODO: marshal entire server entry?

	var serverEntryConfigurationVersion [8]byte
	binary.BigEndian.PutUint64(
		serverEntryConfigurationVersion[:],
		uint64(serverEntry.ConfigurationVersion))
	hash.Write(serverEntryConfigurationVersion[:])
	hash.Write([]byte(serverEntry.LocalTimestamp))

	// TODO: add config.CustomHeaders, which could impact User-Agent header?

	hash.Write([]byte(config.UpstreamProxyURL))

	return hash.Sum(nil)
}

func selectFrontingParameters(serverEntry *protocol.ServerEntry) (string, string, error) {

	frontingDialHost := ""
	frontingHost := ""

	if len(serverEntry.MeekFrontingAddressesRegex) > 0 {

		// Generate a front address based on the regex.

		var err error
		frontingDialHost, err = regen.Generate(serverEntry.MeekFrontingAddressesRegex)
		if err != nil {
			return "", "", common.ContextError(err)
		}

	} else {

		// Randomly select, for this connection attempt, one front address for
		// fronting-capable servers.

		if len(serverEntry.MeekFrontingAddresses) == 0 {
			return "", "", common.ContextError(errors.New("MeekFrontingAddresses is empty"))
		}

		index := prng.Intn(len(serverEntry.MeekFrontingAddresses))
		frontingDialHost = serverEntry.MeekFrontingAddresses[index]
	}

	if len(serverEntry.MeekFrontingHosts) > 0 {

		index := prng.Intn(len(serverEntry.MeekFrontingHosts))
		frontingHost = serverEntry.MeekFrontingHosts[index]

	} else {

		// Backwards compatibility case
		frontingHost = serverEntry.MeekFrontingHost
	}

	return frontingDialHost, frontingHost, nil
}

func selectQUICVersion(p *parameters.ClientParametersSnapshot) string {

	limitQUICVersions := p.QUICVersions(parameters.LimitQUICVersions)

	quicVersions := make([]string, 0)

	for _, quicVersion := range protocol.SupportedQUICVersions {

		if len(limitQUICVersions) > 0 &&
			!common.Contains(limitQUICVersions, quicVersion) {
			continue
		}

		quicVersions = append(quicVersions, quicVersion)
	}

	if len(quicVersions) == 0 {
		return ""
	}

	choice := prng.Intn(len(quicVersions))

	return quicVersions[choice]
}

func makeDialCustomHeaders(
	config *Config,
	p *parameters.ClientParametersSnapshot) http.Header {

	dialCustomHeaders := make(http.Header)
	if config.CustomHeaders != nil {
		for k, v := range config.CustomHeaders {
			dialCustomHeaders[k] = make([]string, len(v))
			copy(dialCustomHeaders[k], v)
		}
	}

	additionalCustomHeaders := p.HTTPHeaders(parameters.AdditionalCustomHeaders)
	if additionalCustomHeaders != nil {
		for k, v := range additionalCustomHeaders {
			dialCustomHeaders[k] = make([]string, len(v))
			copy(dialCustomHeaders[k], v)
		}
	}
	return dialCustomHeaders
}
