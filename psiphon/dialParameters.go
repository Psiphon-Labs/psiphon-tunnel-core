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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	utls "github.com/refraction-networking/utls"
	regen "github.com/zach-klippenstein/goregen"
	"golang.org/x/net/bpf"
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
	ServerEntry             *protocol.ServerEntry `json:"-"`
	NetworkID               string                `json:"-"`
	IsReplay                bool                  `json:"-"`
	CandidateNumber         int                   `json:"-"`
	EstablishedTunnelsCount int                   `json:"-"`

	IsExchanged bool

	LastUsedTimestamp       time.Time
	LastUsedConfigStateHash []byte

	NetworkLatencyMultiplier float64

	TunnelProtocol string

	DirectDialAddress              string
	DialPortNumber                 string
	UpstreamProxyType              string   `json:"-"`
	UpstreamProxyCustomHeaderNames []string `json:"-"`

	BPFProgramName         string
	BPFProgramInstructions []bpf.RawInstruction

	SelectedSSHClientVersion bool
	SSHClientVersion         string
	SSHKEXSeed               *prng.Seed

	ObfuscatorPaddingSeed *prng.Seed

	FragmentorSeed *prng.Seed

	FrontingProviderID string

	MeekFrontingDialAddress   string
	MeekFrontingHost          string
	MeekDialAddress           string
	MeekTransformedHostName   bool
	MeekSNIServerName         string
	MeekHostHeader            string
	MeekObfuscatorPaddingSeed *prng.Seed
	MeekTLSPaddingSize        int
	MeekResolvedIPAddress     atomic.Value `json:"-"`

	SelectedUserAgent bool
	UserAgent         string

	SelectedTLSProfile       bool
	TLSProfile               string
	NoDefaultTLSSessionID    bool
	TLSVersion               string
	RandomizedTLSProfileSeed *prng.Seed

	QUICVersion               string
	QUICDialSNIAddress        string
	ObfuscatedQUICPaddingSeed *prng.Seed

	LivenessTestSeed *prng.Seed

	APIRequestPaddingSeed *prng.Seed

	DialConnMetrics          common.MetricsSource `json:"-"`
	ObfuscatedSSHConnMetrics common.MetricsSource `json:"-"`

	DialDuration time.Duration `json:"-"`

	dialConfig *DialConfig
	meekConfig *MeekConfig
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
	candidateNumber int,
	establishedTunnelsCount int) (*DialParameters, error) {

	networkID := config.GetNetworkID()

	p := config.GetClientParameters().Get()

	ttl := p.Duration(parameters.ReplayDialParametersTTL)
	replayBPF := p.Bool(parameters.ReplayBPF)
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
		NoticeWarning("GetDialParameters failed: %s", err)
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
	// - Must not be using an obsolete TLS profile that is no longer supported.
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
			!bytes.Equal(dialParams.LastUsedConfigStateHash, configStateHash) ||
			(dialParams.TLSProfile != "" &&
				!common.Contains(protocol.SupportedTLSProfiles, dialParams.TLSProfile)) ||
			(dialParams.QUICVersion != "" &&
				!common.Contains(protocol.SupportedQUICVersions, dialParams.QUICVersion))) {

		// In these cases, existing dial parameters are expired or no longer
		// match the config state and so are cleared to avoid rechecking them.

		err = DeleteDialParameters(serverEntry.IpAddress, networkID)
		if err != nil {
			NoticeWarning("DeleteDialParameters failed: %s", err)
		}
		dialParams = nil
	}

	if dialParams != nil {
		if config.DisableReplay ||
			!canReplay(serverEntry, dialParams.TunnelProtocol) {

			// In these ephemeral cases, existing dial parameters may still be valid
			// and used in future establishment phases, and so are retained.

			dialParams = nil
		}
	}

	// IsExchanged:
	//
	// Dial parameters received via client-to-client exchange are partially
	// initialized. Only the exchange fields are retained, and all other dial
	// parameters fields must be initialized. This is not considered or logged as
	// a replay. The exchange case is identified by the IsExchanged flag.
	//
	// When previously stored, IsExchanged dial parameters will have set the same
	// timestamp and state hash used for regular dial parameters and the same
	// logic above should invalidate expired or invalid exchanged dial
	// parameters.
	//
	// Limitation: metrics will indicate when an exchanged server entry is used
	// (source "EXCHANGED") but will not indicate when exchanged dial parameters
	// are used vs. a redial after discarding dial parameters.

	isReplay := (dialParams != nil)
	isExchanged := isReplay && dialParams.IsExchanged

	if !isReplay {
		dialParams = &DialParameters{}
	}

	if isExchanged {
		// Set isReplay to false to cause all non-exchanged values to be
		// initialized; this also causes the exchange case to not log as replay.
		isReplay = false
	}

	// Set IsExchanged so that full dial parameters are stored and replayed upon success.
	dialParams.IsExchanged = false
	dialParams.ServerEntry = serverEntry
	dialParams.NetworkID = networkID
	dialParams.IsReplay = isReplay
	dialParams.CandidateNumber = candidateNumber
	dialParams.EstablishedTunnelsCount = establishedTunnelsCount

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

	// Select a network latency multiplier for this dial. This allows clients to
	// explore and discover timeout values appropriate for the current network.
	// The selection applies per tunnel, to avoid delaying all establishment
	// candidates due to excessive timeouts. The random selection is bounded by a
	// min/max set in tactics and an exponential distribution is used so as to
	// heavily favor values close to the min, which should be set to the
	// singleton NetworkLatencyMultiplier tactics value.
	//
	// Not all existing, persisted DialParameters will have a custom
	// NetworkLatencyMultiplier value. Its zero value will cause the singleton
	// NetworkLatencyMultiplier tactics value to be used instead, which is
	// consistent with the pre-custom multiplier behavior in the older client
	// version which persisted that DialParameters.

	networkLatencyMultiplierMin := p.Float(parameters.NetworkLatencyMultiplierMin)
	networkLatencyMultiplierMax := p.Float(parameters.NetworkLatencyMultiplierMax)

	if !isReplay ||
		// Was selected...
		(dialParams.NetworkLatencyMultiplier != 0.0 &&
			//  But is now outside tactics range...
			(dialParams.NetworkLatencyMultiplier < networkLatencyMultiplierMin ||
				dialParams.NetworkLatencyMultiplier > networkLatencyMultiplierMax)) {

		dialParams.NetworkLatencyMultiplier = prng.ExpFloat64Range(
			networkLatencyMultiplierMin,
			networkLatencyMultiplierMax,
			p.Float(parameters.NetworkLatencyMultiplierLambda))
	}

	if !isReplay && !isExchanged {

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

	if (!isReplay || !replayBPF) &&
		ClientBPFEnabled() &&
		protocol.TunnelProtocolUsesTCP(dialParams.TunnelProtocol) {

		if p.WeightedCoinFlip(parameters.BPFClientTCPProbability) {
			dialParams.BPFProgramName = ""
			dialParams.BPFProgramInstructions = nil
			ok, name, rawInstructions := p.BPFProgram(parameters.BPFClientTCPProgram)
			if ok {
				dialParams.BPFProgramName = name
				dialParams.BPFProgramInstructions = rawInstructions
			}
		}
	}

	if !isReplay || !replaySSH {
		dialParams.SelectedSSHClientVersion = true
		dialParams.SSHClientVersion = values.GetSSHClientVersion()
		dialParams.SSHKEXSeed, err = prng.NewSeed()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if !isReplay || !replayObfuscatorPadding {
		dialParams.ObfuscatorPaddingSeed, err = prng.NewSeed()
		if err != nil {
			return nil, errors.Trace(err)
		}
		if protocol.TunnelProtocolUsesMeek(dialParams.TunnelProtocol) {
			dialParams.MeekObfuscatorPaddingSeed, err = prng.NewSeed()
			if err != nil {
				return nil, errors.Trace(err)
			}
		}
	}

	if !isReplay || !replayFragmentor {
		dialParams.FragmentorSeed, err = prng.NewSeed()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if (!isReplay || !replayTLSProfile) &&
		protocol.TunnelProtocolUsesMeekHTTPS(dialParams.TunnelProtocol) {

		dialParams.SelectedTLSProfile = true

		requireTLS12SessionTickets := protocol.TunnelProtocolRequiresTLS12SessionTickets(
			dialParams.TunnelProtocol)
		isFronted := protocol.TunnelProtocolUsesFrontedMeek(dialParams.TunnelProtocol)
		dialParams.TLSProfile = SelectTLSProfile(
			requireTLS12SessionTickets, isFronted, serverEntry.FrontingProviderID, p)

		dialParams.NoDefaultTLSSessionID = p.WeightedCoinFlip(
			parameters.NoDefaultTLSSessionIDProbability)
	}

	if (!isReplay || !replayRandomizedTLSProfile) &&
		protocol.TunnelProtocolUsesMeekHTTPS(dialParams.TunnelProtocol) &&
		protocol.TLSProfileIsRandomized(dialParams.TLSProfile) {

		dialParams.RandomizedTLSProfileSeed, err = prng.NewSeed()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if (!isReplay || !replayTLSProfile) &&
		protocol.TunnelProtocolUsesMeekHTTPS(dialParams.TunnelProtocol) {

		// Since "Randomized-v2"/CustomTLSProfiles may be TLS 1.2 or TLS 1.3,
		// construct the ClientHello to determine if it's TLS 1.3. This test also
		// covers non-randomized TLS 1.3 profiles. This check must come after
		// dialParams.TLSProfile and dialParams.RandomizedTLSProfileSeed are set. No
		// actual dial is made here.

		utlsClientHelloID, utlsClientHelloSpec, err := getUTLSClientHelloID(
			p, dialParams.TLSProfile)
		if err != nil {
			return nil, errors.Trace(err)
		}

		if protocol.TLSProfileIsRandomized(dialParams.TLSProfile) {
			utlsClientHelloID.Seed = new(utls.PRNGSeed)
			*utlsClientHelloID.Seed = [32]byte(*dialParams.RandomizedTLSProfileSeed)
		}

		dialParams.TLSVersion, err = getClientHelloVersion(
			utlsClientHelloID, utlsClientHelloSpec)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if (!isReplay || !replayFronting) &&
		protocol.TunnelProtocolUsesFrontedMeek(dialParams.TunnelProtocol) {

		dialParams.FrontingProviderID = serverEntry.FrontingProviderID

		dialParams.MeekFrontingDialAddress, dialParams.MeekFrontingHost, err =
			selectFrontingParameters(serverEntry)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if !isReplay || !replayHostname {

		if protocol.TunnelProtocolUsesMeekHTTPS(dialParams.TunnelProtocol) ||
			protocol.TunnelProtocolUsesFrontedMeekQUIC(dialParams.TunnelProtocol) {

			dialParams.MeekSNIServerName = ""
			if p.WeightedCoinFlip(parameters.TransformHostNameProbability) {
				dialParams.MeekSNIServerName = values.GetHostName()
				dialParams.MeekTransformedHostName = true
			}

		} else if protocol.TunnelProtocolUsesMeekHTTP(dialParams.TunnelProtocol) {

			dialParams.MeekHostHeader = ""
			hostname := serverEntry.IpAddress
			if p.WeightedCoinFlip(parameters.TransformHostNameProbability) {
				hostname = values.GetHostName()
				dialParams.MeekTransformedHostName = true
			}
			if serverEntry.MeekServerPort == 80 {
				dialParams.MeekHostHeader = hostname
			} else {
				dialParams.MeekHostHeader = fmt.Sprintf("%s:%d", hostname, serverEntry.MeekServerPort)
			}
		} else if protocol.TunnelProtocolUsesQUIC(dialParams.TunnelProtocol) {

			dialParams.QUICDialSNIAddress = fmt.Sprintf(
				"%s:%d", values.GetHostName(), serverEntry.SshObfuscatedQUICPort)
		}
	}

	if (!isReplay || !replayQUICVersion) &&
		protocol.TunnelProtocolUsesQUIC(dialParams.TunnelProtocol) {

		isFronted := protocol.TunnelProtocolUsesFrontedMeekQUIC(dialParams.TunnelProtocol)
		dialParams.QUICVersion = selectQUICVersion(isFronted, serverEntry.FrontingProviderID, p)
	}

	if (!isReplay || !replayObfuscatedQUIC) &&
		protocol.QUICVersionIsObfuscated(dialParams.QUICVersion) {

		dialParams.ObfuscatedQUICPaddingSeed, err = prng.NewSeed()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if !isReplay || !replayLivenessTest {

		// TODO: initialize only when LivenessTestMaxUp/DownstreamBytes > 0?
		dialParams.LivenessTestSeed, err = prng.NewSeed()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if !isReplay || !replayAPIRequestPadding {
		dialParams.APIRequestPaddingSeed, err = prng.NewSeed()
		if err != nil {
			return nil, errors.Trace(err)
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

	case protocol.TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH:
		dialParams.MeekDialAddress = fmt.Sprintf("%s:443", dialParams.MeekFrontingDialAddress)
		dialParams.MeekHostHeader = dialParams.MeekFrontingHost
		if serverEntry.MeekFrontingDisableSNI {
			dialParams.MeekSNIServerName = ""
			// When SNI is omitted, the transformed host name is not used.
			dialParams.MeekTransformedHostName = false
		} else if !dialParams.MeekTransformedHostName {
			dialParams.MeekSNIServerName = dialParams.MeekFrontingDialAddress
		}

	case protocol.TUNNEL_PROTOCOL_MARIONETTE_OBFUSCATED_SSH:
		// Note: port comes from marionnete "format"
		dialParams.DirectDialAddress = serverEntry.IpAddress

	case protocol.TUNNEL_PROTOCOL_FRONTED_MEEK:
		dialParams.MeekDialAddress = fmt.Sprintf("%s:443", dialParams.MeekFrontingDialAddress)
		dialParams.MeekHostHeader = dialParams.MeekFrontingHost
		if serverEntry.MeekFrontingDisableSNI {
			dialParams.MeekSNIServerName = ""
			// When SNI is omitted, the transformed host name is not used.
			dialParams.MeekTransformedHostName = false
		} else if !dialParams.MeekTransformedHostName {
			dialParams.MeekSNIServerName = dialParams.MeekFrontingDialAddress
		}

	case protocol.TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP:
		dialParams.MeekDialAddress = fmt.Sprintf("%s:80", dialParams.MeekFrontingDialAddress)
		dialParams.MeekHostHeader = dialParams.MeekFrontingHost
		// For FRONTED HTTP, the Host header cannot be transformed.
		dialParams.MeekTransformedHostName = false

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
		return nil, errors.Tracef(
			"unknown tunnel protocol: %s", dialParams.TunnelProtocol)

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
			dialParams.SelectedUserAgent, dialParams.UserAgent = selectUserAgentIfUnset(p, dialCustomHeaders)
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
		DiagnosticID:                  serverEntry.GetDiagnosticID(),
		UpstreamProxyURL:              config.UpstreamProxyURL,
		CustomHeaders:                 dialCustomHeaders,
		BPFProgramInstructions:        dialParams.BPFProgramInstructions,
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
			DiagnosticID:                  serverEntry.GetDiagnosticID(),
			ClientParameters:              config.clientParameters,
			DialAddress:                   dialParams.MeekDialAddress,
			UseQUIC:                       protocol.TunnelProtocolUsesFrontedMeekQUIC(dialParams.TunnelProtocol),
			QUICVersion:                   dialParams.QUICVersion,
			UseHTTPS:                      protocol.TunnelProtocolUsesMeekHTTPS(dialParams.TunnelProtocol),
			TLSProfile:                    dialParams.TLSProfile,
			NoDefaultTLSSessionID:         dialParams.NoDefaultTLSSessionID,
			RandomizedTLSProfileSeed:      dialParams.RandomizedTLSProfileSeed,
			UseObfuscatedSessionTickets:   dialParams.TunnelProtocol == protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET,
			SNIServerName:                 dialParams.MeekSNIServerName,
			HostHeader:                    dialParams.MeekHostHeader,
			TransformedHostName:           dialParams.MeekTransformedHostName,
			ClientTunnelProtocol:          dialParams.TunnelProtocol,
			MeekCookieEncryptionPublicKey: serverEntry.MeekCookieEncryptionPublicKey,
			MeekObfuscatedKey:             serverEntry.MeekObfuscatedKey,
			MeekObfuscatorPaddingSeed:     dialParams.MeekObfuscatorPaddingSeed,
			NetworkLatencyMultiplier:      dialParams.NetworkLatencyMultiplier,
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

// GetNetworkType returns a network type name, suitable for metrics, which is
// derived from the network ID.
func (dialParams *DialParameters) GetNetworkType() string {

	// Unlike the logic in loggingNetworkIDGetter.GetNetworkID, we don't take the
	// arbitrary text before the first "-" since some platforms without network
	// detection support stub in random values to enable tactics. Instead we
	// check for and use the common network type prefixes currently used in
	// NetworkIDGetter implementations.

	if strings.HasPrefix(dialParams.NetworkID, "WIFI") {
		return "WIFI"
	}
	if strings.HasPrefix(dialParams.NetworkID, "MOBILE") {
		return "MOBILE"
	}
	return "UNKNOWN"
}

func (dialParams *DialParameters) Succeeded() {

	// When TTL is 0, don't store dial parameters.
	if dialParams.LastUsedTimestamp.IsZero() {
		return
	}

	NoticeInfo("Set dial parameters for %s", dialParams.ServerEntry.GetDiagnosticID())
	err := SetDialParameters(dialParams.ServerEntry.IpAddress, dialParams.NetworkID, dialParams)
	if err != nil {
		NoticeWarning("SetDialParameters failed: %s", err)
	}
}

func (dialParams *DialParameters) Failed(config *Config) {

	// When a tunnel fails, and the dial is a replay, clear the stored dial
	// parameters which are now presumed to be blocked, impaired or otherwise
	// no longer effective.
	//
	// It may be the case that a dial is not using stored dial parameters
	// (!IsReplay), and in this case we retain those dial parameters since they
	// were not exercised and may still be effective.
	//
	// Failed tunnel dial parameters may be retained with a configurable
	// probability; this is intended to help mitigate false positive failures due
	// to, e.g., temporary network disruptions or server load limiting.

	if dialParams.IsReplay &&
		!config.GetClientParameters().Get().WeightedCoinFlip(
			parameters.ReplayRetainFailedProbability) {

		NoticeInfo("Delete dial parameters for %s", dialParams.ServerEntry.GetDiagnosticID())
		err := DeleteDialParameters(dialParams.ServerEntry.IpAddress, dialParams.NetworkID)
		if err != nil {
			NoticeWarning("DeleteDialParameters failed: %s", err)
		}
	}
}

func (dialParams *DialParameters) GetTLSVersionForMetrics() string {
	tlsVersion := dialParams.TLSVersion
	if dialParams.NoDefaultTLSSessionID {
		tlsVersion += "-no_def_id"
	}
	return tlsVersion
}

// ExchangedDialParameters represents the subset of DialParameters that is
// shared in a client-to-client exchange of server connection info.
//
// The purpose of client-to-client exchange if for one user that can connect
// to help another user that cannot connect by sharing their connected
// configuration, including the server entry and dial parameters.
//
// There are two concerns regarding which dial parameter fields are safe to
// exchange:
//
// - Unlike signed server entries, there's no independent trust anchor
//   that can certify that the exchange data is valid.
//
// - While users should only perform the exchange with trusted peers,
//   the user's trust in their peer may be misplaced.
//
// This presents the possibility of attack such as the peer sending dial
// parameters that could be used to trace/monitor/flag the importer; or
// sending dial parameters, including dial address and SNI, to cause the peer
// to appear to connect to a banned service.
//
// To mitigate these risks, only a subset of dial parameters are exchanged.
// When exchanged dial parameters and imported and used, all unexchanged
// parameters are generated locally. At this time, only the tunnel protocol is
// exchanged. We consider tunnel protocol selection one of the key connection
// success factors.
//
// In addition, the exchange peers may not be on the same network with the
// same blocking and circumvention characteristics, which is another reason
// to limit exchanged dial parameter values to broadly applicable fields.
//
// Unlike the exchanged (and otherwise acquired) server entry,
// ExchangedDialParameters does not use the ServerEntry_Fields_ representation
// which allows older clients to receive and store new, unknown fields. Such a
// facility is less useful in this case, since exchanged dial parameters and
// used immediately and have a short lifespan.
//
// TODO: exchange more dial parameters, such as TLS profile, QUIC version, etc.
type ExchangedDialParameters struct {
	TunnelProtocol string
}

// NewExchangedDialParameters creates a new ExchangedDialParameters from a
// DialParameters, including only the exchanged values.
// NewExchangedDialParameters assumes the input DialParameters has been
// initialized and populated by MakeDialParameters.
func NewExchangedDialParameters(dialParams *DialParameters) *ExchangedDialParameters {
	return &ExchangedDialParameters{
		TunnelProtocol: dialParams.TunnelProtocol,
	}
}

// Validate checks that the ExchangedDialParameters contains only valid values
// and is compatible with the specified server entry.
func (dialParams *ExchangedDialParameters) Validate(serverEntry *protocol.ServerEntry) error {
	if !common.Contains(protocol.SupportedTunnelProtocols, dialParams.TunnelProtocol) {
		return errors.Tracef("unknown tunnel protocol: %s", dialParams.TunnelProtocol)
	}
	if !serverEntry.SupportsProtocol(dialParams.TunnelProtocol) {
		return errors.Tracef("unsupported tunnel protocol: %s", dialParams.TunnelProtocol)
	}
	return nil
}

// MakeDialParameters creates a new, partially intitialized DialParameters
// from the values in ExchangedDialParameters. The returned DialParameters
// must not be used directly for dialing. It is intended to be stored, and
// then later fully initialized by MakeDialParameters.
func (dialParams *ExchangedDialParameters) MakeDialParameters(
	config *Config,
	p parameters.ClientParametersAccessor,
	serverEntry *protocol.ServerEntry) *DialParameters {

	return &DialParameters{
		IsExchanged:             true,
		LastUsedTimestamp:       time.Now(),
		LastUsedConfigStateHash: getConfigStateHash(config, p, serverEntry),
		TunnelProtocol:          dialParams.TunnelProtocol,
	}
}

func getConfigStateHash(
	config *Config,
	p parameters.ClientParametersAccessor,
	serverEntry *protocol.ServerEntry) []byte {

	// The config state hash should reflect config, tactics, and server entry
	// settings that impact the dial parameters. The hash should change if any
	// of these input values change in a way that invalidates any stored dial
	// parameters.

	// MD5 hash is used solely as a data checksum and not for any security
	// purpose.
	hash := md5.New()

	// Add a hash of relevant config fields.
	// Limitation: the config hash may change even when tactics will override the
	// changed config field.
	hash.Write(config.dialParametersHash)

	// Add the active tactics tag.
	hash.Write([]byte(p.Tag()))

	// Add the server entry version and local timestamp, both of which should
	// change when the server entry contents change and/or a new local copy is
	// imported.
	// TODO: marshal entire server entry?
	var serverEntryConfigurationVersion [8]byte
	binary.BigEndian.PutUint64(
		serverEntryConfigurationVersion[:],
		uint64(serverEntry.ConfigurationVersion))
	hash.Write(serverEntryConfigurationVersion[:])
	hash.Write([]byte(serverEntry.LocalTimestamp))

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
			return "", "", errors.Trace(err)
		}

	} else {

		// Randomly select, for this connection attempt, one front address for
		// fronting-capable servers.

		if len(serverEntry.MeekFrontingAddresses) == 0 {
			return "", "", errors.TraceNew("MeekFrontingAddresses is empty")
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

func selectQUICVersion(
	isFronted bool,
	frontingProviderID string,
	p parameters.ClientParametersAccessor) string {

	limitQUICVersions := p.QUICVersions(parameters.LimitQUICVersions)

	var disableQUICVersions protocol.QUICVersions

	if isFronted {
		if frontingProviderID == "" {
			// Legacy server entry case
			disableQUICVersions = protocol.QUICVersions{protocol.QUIC_VERSION_IETF_DRAFT24}
		} else {
			disableQUICVersions = p.LabeledQUICVersions(
				parameters.DisableFrontingProviderQUICVersions, frontingProviderID)
		}
	}

	quicVersions := make([]string, 0)

	for _, quicVersion := range protocol.SupportedQUICVersions {

		if len(limitQUICVersions) > 0 &&
			!common.Contains(limitQUICVersions, quicVersion) {
			continue
		}

		if isFronted &&
			protocol.QUICVersionIsObfuscated(quicVersion) {
			continue
		}

		if common.Contains(disableQUICVersions, quicVersion) {
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

// selectUserAgentIfUnset selects a User-Agent header if one is not set.
func selectUserAgentIfUnset(
	p parameters.ClientParametersAccessor, headers http.Header) (bool, string) {

	if _, ok := headers["User-Agent"]; !ok {

		userAgent := ""
		if p.WeightedCoinFlip(parameters.PickUserAgentProbability) {
			userAgent = values.GetUserAgent()
		}

		return true, userAgent
	}

	return false, ""
}

func makeDialCustomHeaders(
	config *Config,
	p parameters.ClientParametersAccessor) http.Header {

	dialCustomHeaders := make(http.Header)
	if config.CustomHeaders != nil {
		for k, v := range config.CustomHeaders {
			dialCustomHeaders[k] = make([]string, len(v))
			copy(dialCustomHeaders[k], v)
		}
	}

	additionalCustomHeaders := p.HTTPHeaders(parameters.AdditionalCustomHeaders)
	for k, v := range additionalCustomHeaders {
		dialCustomHeaders[k] = make([]string, len(v))
		copy(dialCustomHeaders[k], v)
	}
	return dialCustomHeaders
}
