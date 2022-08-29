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
	"context"
	"crypto/md5"
	"encoding/binary"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	utls "github.com/Psiphon-Labs/utls"
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
	MeekVerifyServerName      string
	MeekVerifyPins            []string
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

	QUICVersion                 string
	QUICDialSNIAddress          string
	QUICClientHelloSeed         *prng.Seed
	ObfuscatedQUICPaddingSeed   *prng.Seed
	QUICDisablePathMTUDiscovery bool

	ConjureCachedRegistrationTTL        time.Duration
	ConjureAPIRegistration              bool
	ConjureAPIRegistrarBidirectionalURL string
	ConjureAPIRegistrarDelay            time.Duration
	ConjureDecoyRegistration            bool
	ConjureDecoyRegistrarDelay          time.Duration
	ConjureDecoyRegistrarWidth          int
	ConjureTransport                    string

	LivenessTestSeed *prng.Seed

	APIRequestPaddingSeed *prng.Seed

	HoldOffTunnelDuration time.Duration

	DialConnMetrics          common.MetricsSource       `json:"-"`
	DialConnNoticeMetrics    common.NoticeMetricsSource `json:"-"`
	ObfuscatedSSHConnMetrics common.MetricsSource       `json:"-"`

	DialDuration time.Duration `json:"-"`

	resolver          *resolver.Resolver `json:"-"`
	ResolveParameters *resolver.ResolveParameters

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
	upstreamProxyErrorCallback func(error),
	canReplay func(serverEntry *protocol.ServerEntry, replayProtocol string) bool,
	selectProtocol func(serverEntry *protocol.ServerEntry) (string, bool),
	serverEntry *protocol.ServerEntry,
	isTactics bool,
	candidateNumber int,
	establishedTunnelsCount int) (*DialParameters, error) {

	networkID := config.GetNetworkID()

	p := config.GetParameters().Get()

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
	replayConjureRegistration := p.Bool(parameters.ReplayConjureRegistration)
	replayConjureTransport := p.Bool(parameters.ReplayConjureTransport)
	replayLivenessTest := p.Bool(parameters.ReplayLivenessTest)
	replayUserAgent := p.Bool(parameters.ReplayUserAgent)
	replayAPIRequestPadding := p.Bool(parameters.ReplayAPIRequestPadding)
	replayHoldOffTunnel := p.Bool(parameters.ReplayHoldOffTunnel)
	replayResolveParameters := p.Bool(parameters.ReplayResolveParameters)

	// Check for existing dial parameters for this server/network ID.

	dialParams, err := GetDialParameters(
		config, serverEntry.IpAddress, networkID)
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
	// - Must be using the latest Conjure API URL.
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
				!common.Contains(protocol.SupportedQUICVersions, dialParams.QUICVersion)) ||

			// Legacy clients use ConjureAPIRegistrarURL with
			// gotapdance.tapdance.APIRegistrar and new clients use
			// ConjureAPIRegistrarBidirectionalURL with
			// gotapdance.tapdance.APIRegistrarBidirectional. Updated clients
			// may have replay dial parameters with the old
			// ConjureAPIRegistrarURL field, which is now ignored. In this
			// case, ConjureAPIRegistrarBidirectionalURL will be blank. Reset
			// this replay.
			(dialParams.ConjureAPIRegistration && dialParams.ConjureAPIRegistrarBidirectionalURL == "")) {

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

	// Point to the current resolver to be used in dials.
	dialParams.resolver = config.GetResolver()
	if dialParams.resolver == nil {
		return nil, errors.TraceNew("missing resolver")
	}

	if isExchanged {
		// Set isReplay to false to cause all non-exchanged values to be
		// initialized; this also causes the exchange case to not log as replay.
		isReplay = false
	}

	// Set IsExchanged such that full dial parameters are stored and replayed
	// upon success.
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
	// For NetworkLatencyMultiplierLambda close to 2.0, values near min are
	// very approximately 10x more likely to be selected than values near
	// max, while for NetworkLatencyMultiplierLambda close to 0.1, the
	// distribution is close to uniform.
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

	// After this point, any tactics parameters that apply the network latency
	// multiplier will use this selected value.
	p = config.GetParameters().GetCustom(dialParams.NetworkLatencyMultiplier)

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

	// Skip this candidate when the clients tactics restrict usage of the
	// fronting provider ID. See the corresponding server-side enforcement
	// comments in server.TacticsListener.accept.
	if protocol.TunnelProtocolUsesFrontedMeek(dialParams.TunnelProtocol) &&
		common.Contains(
			p.Strings(parameters.RestrictFrontingProviderIDs),
			dialParams.ServerEntry.FrontingProviderID) {
		if p.WeightedCoinFlip(
			parameters.RestrictFrontingProviderIDsClientProbability) {

			// When skipping, return nil/nil as no error should be logged.
			// NoticeSkipServerEntry emits each skip reason, regardless
			// of server entry, at most once per session.

			NoticeSkipServerEntry(
				"restricted fronting provider ID: %s",
				dialParams.ServerEntry.FrontingProviderID)

			return nil, nil
		}
	}

	if config.UseUpstreamProxy() {

		// When UpstreamProxy is configured, ServerEntry.GetSupportedProtocols, when
		// called via selectProtocol, will filter out protocols such that will not
		// select a protocol incompatible with UpstreamProxy. This additional check
		// will catch cases where selectProtocol does not apply this filter.
		if !protocol.TunnelProtocolSupportsUpstreamProxy(dialParams.TunnelProtocol) {

			NoticeSkipServerEntry(
				"protocol does not support upstream proxy: %s",
				dialParams.TunnelProtocol)

			return nil, nil
		}

		// Skip this candidate when the server entry is not to be used with an
		// upstream proxy. By not exposing servers from sources that are
		// relatively hard to enumerate, this mechanism mitigates the risk of
		// a malicious upstream proxy enumerating Psiphon servers. Populate
		// the allowed sources with fronted servers to provide greater
		// blocking resistence for clients using upstream proxy clients that
		// are subject to blocking.
		source := dialParams.ServerEntry.LocalSource
		if !protocol.AllowServerEntrySourceWithUpstreamProxy(source) &&
			!p.Bool(parameters.UpstreamProxyAllowAllServerEntrySources) {

			NoticeSkipServerEntry(
				"server entry source disallowed with upstream proxy: %s",
				source)

			return nil, nil
		}
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

	if (!isReplay || !replayConjureRegistration) &&
		protocol.TunnelProtocolUsesConjure(dialParams.TunnelProtocol) {

		dialParams.ConjureCachedRegistrationTTL = p.Duration(parameters.ConjureCachedRegistrationTTL)

		apiURL := p.String(parameters.ConjureAPIRegistrarBidirectionalURL)
		decoyWidth := p.Int(parameters.ConjureDecoyRegistrarWidth)

		dialParams.ConjureAPIRegistration = apiURL != ""
		dialParams.ConjureDecoyRegistration = decoyWidth != 0

		// We select only one of API or decoy registration. When both are enabled,
		// ConjureDecoyRegistrarProbability determines the probability of using
		// decoy registration.
		//
		// In general, we disable retries in gotapdance and rely on Psiphon
		// establishment to try/retry different registration schemes. This allows us
		// to control the proportion of registration types attempted. And, in good
		// network conditions, individual candidates are most likely to be cancelled
		// before they exhaust their retry options.

		if dialParams.ConjureAPIRegistration && dialParams.ConjureDecoyRegistration {
			if p.WeightedCoinFlip(parameters.ConjureDecoyRegistrarProbability) {
				dialParams.ConjureAPIRegistration = false
			}
		}

		if dialParams.ConjureAPIRegistration {

			// While Conjure API registration uses MeekConn and specifies common meek
			// parameters, the meek address and SNI configuration is implemented in this
			// code block and not in common code blocks below. The exception is TLS
			// configuration.
			//
			// Accordingly, replayFronting/replayHostname have no effect on Conjure API
			// registration replay.

			dialParams.ConjureAPIRegistrarBidirectionalURL = apiURL

			frontingSpecs := p.FrontingSpecs(parameters.ConjureAPIRegistrarFrontingSpecs)
			dialParams.FrontingProviderID,
				dialParams.MeekFrontingDialAddress,
				dialParams.MeekSNIServerName,
				dialParams.MeekVerifyServerName,
				dialParams.MeekVerifyPins,
				dialParams.MeekFrontingHost,
				err = frontingSpecs.SelectParameters()
			if err != nil {
				return nil, errors.Trace(err)
			}

			dialParams.MeekDialAddress = net.JoinHostPort(dialParams.MeekFrontingDialAddress, "443")
			dialParams.MeekHostHeader = dialParams.MeekFrontingHost

			// For a FrontingSpec, an SNI value of "" indicates to disable/omit SNI, so
			// never transform in that case.
			if dialParams.MeekSNIServerName != "" {
				if p.WeightedCoinFlip(parameters.TransformHostNameProbability) {
					dialParams.MeekSNIServerName = selectHostName(dialParams.TunnelProtocol, p)
					dialParams.MeekTransformedHostName = true
				}
			}

			// The minimum delay value is determined by the Conjure station, which
			// performs an asynchronous "liveness test" against the selected phantom
			// IPs. The min/max range allows us to introduce some jitter so that we
			// don't present a trivial inter-flow fingerprint: CDN connection, fixed
			// delay, phantom dial.

			minDelay := p.Duration(parameters.ConjureAPIRegistrarMinDelay)
			maxDelay := p.Duration(parameters.ConjureAPIRegistrarMaxDelay)
			dialParams.ConjureAPIRegistrarDelay = prng.Period(minDelay, maxDelay)

		} else if dialParams.ConjureDecoyRegistration {

			dialParams.ConjureDecoyRegistrarWidth = decoyWidth
			minDelay := p.Duration(parameters.ConjureDecoyRegistrarMinDelay)
			maxDelay := p.Duration(parameters.ConjureDecoyRegistrarMaxDelay)
			dialParams.ConjureAPIRegistrarDelay = prng.Period(minDelay, maxDelay)

		} else {

			return nil, errors.TraceNew("no Conjure registrar configured")
		}
	}

	if (!isReplay || !replayConjureTransport) &&
		protocol.TunnelProtocolUsesConjure(dialParams.TunnelProtocol) {

		dialParams.ConjureTransport = protocol.CONJURE_TRANSPORT_MIN_OSSH
		if p.WeightedCoinFlip(
			parameters.ConjureTransportObfs4Probability) {
			dialParams.ConjureTransport = protocol.CONJURE_TRANSPORT_OBFS4_OSSH
		}
	}

	usingTLS := protocol.TunnelProtocolUsesMeekHTTPS(dialParams.TunnelProtocol) ||
		dialParams.ConjureAPIRegistration

	if (!isReplay || !replayTLSProfile) && usingTLS {

		dialParams.SelectedTLSProfile = true

		requireTLS12SessionTickets := protocol.TunnelProtocolRequiresTLS12SessionTickets(
			dialParams.TunnelProtocol)

		isFronted := protocol.TunnelProtocolUsesFrontedMeek(dialParams.TunnelProtocol) ||
			dialParams.ConjureAPIRegistration

		dialParams.TLSProfile = SelectTLSProfile(
			requireTLS12SessionTickets, isFronted, serverEntry.FrontingProviderID, p)

		dialParams.NoDefaultTLSSessionID = p.WeightedCoinFlip(
			parameters.NoDefaultTLSSessionIDProbability)
	}

	if (!isReplay || !replayRandomizedTLSProfile) && usingTLS &&
		protocol.TLSProfileIsRandomized(dialParams.TLSProfile) {

		dialParams.RandomizedTLSProfileSeed, err = prng.NewSeed()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if (!isReplay || !replayTLSProfile) && usingTLS {

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
				dialParams.MeekSNIServerName = selectHostName(dialParams.TunnelProtocol, p)
				dialParams.MeekTransformedHostName = true
			}

		} else if protocol.TunnelProtocolUsesMeekHTTP(dialParams.TunnelProtocol) {

			dialParams.MeekHostHeader = ""
			hostname := serverEntry.IpAddress
			if p.WeightedCoinFlip(parameters.TransformHostNameProbability) {
				hostname = selectHostName(dialParams.TunnelProtocol, p)
				dialParams.MeekTransformedHostName = true
			}
			if serverEntry.MeekServerPort == 80 {
				dialParams.MeekHostHeader = hostname
			} else {
				dialParams.MeekHostHeader = net.JoinHostPort(
					hostname, strconv.Itoa(serverEntry.MeekServerPort))
			}
		} else if protocol.TunnelProtocolUsesQUIC(dialParams.TunnelProtocol) {

			dialParams.QUICDialSNIAddress = net.JoinHostPort(
				selectHostName(dialParams.TunnelProtocol, p),
				strconv.Itoa(serverEntry.SshObfuscatedQUICPort))
		}
	}

	if (!isReplay || !replayQUICVersion) &&
		protocol.TunnelProtocolUsesQUIC(dialParams.TunnelProtocol) {

		isFronted := protocol.TunnelProtocolUsesFrontedMeekQUIC(dialParams.TunnelProtocol)
		dialParams.QUICVersion = selectQUICVersion(isFronted, serverEntry, p)

		if protocol.QUICVersionHasRandomizedClientHello(dialParams.QUICVersion) {
			dialParams.QUICClientHelloSeed, err = prng.NewSeed()
			if err != nil {
				return nil, errors.Trace(err)
			}
		}

		dialParams.QUICDisablePathMTUDiscovery =
			protocol.QUICVersionUsesPathMTUDiscovery(dialParams.QUICVersion) &&
				p.WeightedCoinFlip(parameters.QUICDisableClientPathMTUDiscoveryProbability)
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

	// Initialize dialParams.ResolveParameters for dials that will resolve
	// domain names, which currently includes fronted meek and Conjure API
	// registration, where the dial address is not an IP address.
	//
	// dialParams.ResolveParameters must be nil when the dial address is an IP
	// address to ensure that no DNS dial parameters are reported in metrics
	// or diagnostics when when no domain is resolved.

	useResolver := (protocol.TunnelProtocolUsesFrontedMeek(dialParams.TunnelProtocol) ||
		dialParams.ConjureAPIRegistration) &&
		net.ParseIP(dialParams.MeekFrontingDialAddress) == nil

	if (!isReplay || !replayResolveParameters) && useResolver {

		dialParams.ResolveParameters, err = dialParams.resolver.MakeResolveParameters(
			p, dialParams.FrontingProviderID)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if !isReplay || !replayHoldOffTunnel {

		if common.Contains(
			p.TunnelProtocols(parameters.HoldOffTunnelProtocols), dialParams.TunnelProtocol) ||

			(protocol.TunnelProtocolUsesFrontedMeek(dialParams.TunnelProtocol) &&
				common.Contains(
					p.Strings(parameters.HoldOffTunnelFrontingProviderIDs),
					dialParams.FrontingProviderID)) {

			if p.WeightedCoinFlip(parameters.HoldOffTunnelProbability) {

				dialParams.HoldOffTunnelDuration = prng.Period(
					p.Duration(parameters.HoldOffTunnelMinDuration),
					p.Duration(parameters.HoldOffTunnelMaxDuration))
			}
		}

	}

	// Set dial address fields. This portion of configuration is
	// deterministic, given the parameters established or replayed so far.

	dialPortNumber, err := serverEntry.GetDialPortNumber(dialParams.TunnelProtocol)
	if err != nil {
		return nil, errors.Trace(err)
	}

	dialParams.DialPortNumber = strconv.Itoa(dialPortNumber)

	switch dialParams.TunnelProtocol {

	case protocol.TUNNEL_PROTOCOL_SSH,
		protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH,
		protocol.TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH,
		protocol.TUNNEL_PROTOCOL_CONJURE_OBFUSCATED_SSH,
		protocol.TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH:

		dialParams.DirectDialAddress = net.JoinHostPort(serverEntry.IpAddress, dialParams.DialPortNumber)

	case protocol.TUNNEL_PROTOCOL_FRONTED_MEEK,
		protocol.TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH:

		dialParams.MeekDialAddress = net.JoinHostPort(dialParams.MeekFrontingDialAddress, dialParams.DialPortNumber)
		dialParams.MeekHostHeader = dialParams.MeekFrontingHost
		if serverEntry.MeekFrontingDisableSNI {
			dialParams.MeekSNIServerName = ""
			// When SNI is omitted, the transformed host name is not used.
			dialParams.MeekTransformedHostName = false
		} else if !dialParams.MeekTransformedHostName {
			dialParams.MeekSNIServerName = dialParams.MeekFrontingDialAddress
		}

	case protocol.TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP:

		dialParams.MeekDialAddress = net.JoinHostPort(dialParams.MeekFrontingDialAddress, dialParams.DialPortNumber)
		dialParams.MeekHostHeader = dialParams.MeekFrontingHost
		// For FRONTED HTTP, the Host header cannot be transformed.
		dialParams.MeekTransformedHostName = false

	case protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK:

		dialParams.MeekDialAddress = net.JoinHostPort(serverEntry.IpAddress, dialParams.DialPortNumber)
		if !dialParams.MeekTransformedHostName {
			if dialPortNumber == 80 {
				dialParams.MeekHostHeader = serverEntry.IpAddress
			} else {
				dialParams.MeekHostHeader = dialParams.MeekDialAddress
			}
		}

	case protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
		protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET:

		dialParams.MeekDialAddress = net.JoinHostPort(serverEntry.IpAddress, dialParams.DialPortNumber)
		if !dialParams.MeekTransformedHostName {
			// Note: IP address in SNI field will be omitted.
			dialParams.MeekSNIServerName = serverEntry.IpAddress
		}
		if dialPortNumber == 443 {
			dialParams.MeekHostHeader = serverEntry.IpAddress
		} else {
			dialParams.MeekHostHeader = dialParams.MeekDialAddress
		}

	default:
		return nil, errors.Tracef(
			"unknown tunnel protocol: %s", dialParams.TunnelProtocol)

	}

	if protocol.TunnelProtocolUsesMeek(dialParams.TunnelProtocol) {

		host, _, _ := net.SplitHostPort(dialParams.MeekDialAddress)

		if p.Bool(parameters.MeekDialDomainsOnly) {
			if net.ParseIP(host) != nil {
				// No error, as this is a "not supported" case.
				return nil, nil
			}
		}

		// The underlying TLS implementation will automatically omit SNI for
		// IP address server name values; we have this explicit check here so
		// we record the correct value for stats.
		if net.ParseIP(dialParams.MeekSNIServerName) != nil {
			dialParams.MeekSNIServerName = ""
		}
	}

	// Initialize/replay User-Agent header for HTTP upstream proxy and meek protocols.

	if config.UseUpstreamProxy() {
		// Note: UpstreamProxyURL will be validated in the dial
		proxyURL, err := common.SafeParseURL(config.UpstreamProxyURL)
		if err == nil {
			dialParams.UpstreamProxyType = proxyURL.Scheme
		}
	}

	dialCustomHeaders := makeDialCustomHeaders(config, p)

	if protocol.TunnelProtocolUsesMeek(dialParams.TunnelProtocol) ||
		dialParams.UpstreamProxyType == "http" ||
		dialParams.ConjureAPIRegistration {

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

	// Custom ResolveParameters are set only when useResolver is true, but
	// DialConfig.ResolveIP is required and wired up unconditionally. Any
	// misconfigured or miscoded domain dial cases will use default
	// ResolveParameters.
	//
	// ResolveIP will use the networkID obtained above, as it will be used
	// almost immediately, instead of incurring the overhead of calling
	// GetNetworkID again.
	resolveIP := func(ctx context.Context, hostname string) ([]net.IP, error) {
		IPs, err := dialParams.resolver.ResolveIP(
			ctx,
			networkID,
			dialParams.ResolveParameters,
			hostname)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return IPs, nil
	}

	dialParams.dialConfig = &DialConfig{
		DiagnosticID:                  serverEntry.GetDiagnosticID(),
		UpstreamProxyURL:              config.UpstreamProxyURL,
		CustomHeaders:                 dialCustomHeaders,
		BPFProgramInstructions:        dialParams.BPFProgramInstructions,
		DeviceBinder:                  config.deviceBinder,
		IPv6Synthesizer:               config.IPv6Synthesizer,
		ResolveIP:                     resolveIP,
		TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
		FragmentorConfig:              fragmentor.NewUpstreamConfig(p, dialParams.TunnelProtocol, dialParams.FragmentorSeed),
		UpstreamProxyErrorCallback:    upstreamProxyErrorCallback,
	}

	// Unconditionally initialize MeekResolvedIPAddress, so a valid string can
	// always be read.
	dialParams.MeekResolvedIPAddress.Store("")

	if protocol.TunnelProtocolUsesMeek(dialParams.TunnelProtocol) ||
		dialParams.ConjureAPIRegistration {

		dialParams.meekConfig = &MeekConfig{
			DiagnosticID:                  serverEntry.GetDiagnosticID(),
			Parameters:                    config.GetParameters(),
			DialAddress:                   dialParams.MeekDialAddress,
			UseQUIC:                       protocol.TunnelProtocolUsesFrontedMeekQUIC(dialParams.TunnelProtocol),
			QUICVersion:                   dialParams.QUICVersion,
			QUICClientHelloSeed:           dialParams.QUICClientHelloSeed,
			QUICDisablePathMTUDiscovery:   dialParams.QUICDisablePathMTUDiscovery,
			UseHTTPS:                      usingTLS,
			TLSProfile:                    dialParams.TLSProfile,
			LegacyPassthrough:             serverEntry.ProtocolUsesLegacyPassthrough(dialParams.TunnelProtocol),
			NoDefaultTLSSessionID:         dialParams.NoDefaultTLSSessionID,
			RandomizedTLSProfileSeed:      dialParams.RandomizedTLSProfileSeed,
			UseObfuscatedSessionTickets:   dialParams.TunnelProtocol == protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET,
			SNIServerName:                 dialParams.MeekSNIServerName,
			VerifyServerName:              dialParams.MeekVerifyServerName,
			VerifyPins:                    dialParams.MeekVerifyPins,
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
			dialParams.meekConfig.Mode = MeekModeObfuscatedRoundTrip
		} else if dialParams.ConjureAPIRegistration {
			dialParams.meekConfig.Mode = MeekModePlaintextRoundTrip
		} else {
			dialParams.meekConfig.Mode = MeekModeRelay
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
		!config.GetParameters().Get().WeightedCoinFlip(
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
	p parameters.ParametersAccessor,
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
	p parameters.ParametersAccessor,
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

func selectFrontingParameters(
	serverEntry *protocol.ServerEntry) (string, string, error) {

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
	serverEntry *protocol.ServerEntry,
	p parameters.ParametersAccessor) string {

	limitQUICVersions := p.QUICVersions(parameters.LimitQUICVersions)

	var disableQUICVersions protocol.QUICVersions

	if isFronted {
		if serverEntry.FrontingProviderID == "" {
			// Legacy server entry case
			disableQUICVersions = protocol.QUICVersions{
				protocol.QUIC_VERSION_V1,
				protocol.QUIC_VERSION_RANDOMIZED_V1,
				protocol.QUIC_VERSION_OBFUSCATED_V1,
				protocol.QUIC_VERSION_DECOY_V1,
			}
		} else {
			disableQUICVersions = p.LabeledQUICVersions(
				parameters.DisableFrontingProviderQUICVersions,
				serverEntry.FrontingProviderID)
		}
	}

	quicVersions := make([]string, 0)

	// Don't use gQUIC versions when the server entry specifies QUICv1-only.
	supportedQUICVersions := protocol.SupportedQUICVersions
	if serverEntry.SupportsOnlyQUICv1() {
		supportedQUICVersions = protocol.SupportedQUICv1Versions
	}

	for _, quicVersion := range supportedQUICVersions {

		if len(limitQUICVersions) > 0 &&
			!common.Contains(limitQUICVersions, quicVersion) {
			continue
		}

		// Both tactics and the server entry can specify LimitQUICVersions. In
		// tactics, the parameter is intended to direct certain clients to
		// use a successful protocol variant. In the server entry, the
		// parameter may be used to direct all clients to send
		// consistent-looking protocol variants to a particular server; e.g.,
		// only regular QUIC, or only obfuscated QUIC.
		//
		// The isFronted/QUICVersionIsObfuscated logic predates
		// ServerEntry.LimitQUICVersions; ServerEntry.LimitQUICVersions could
		// now be used to achieve a similar outcome.
		if len(serverEntry.LimitQUICVersions) > 0 &&
			!common.Contains(serverEntry.LimitQUICVersions, quicVersion) {
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
	p parameters.ParametersAccessor, headers http.Header) (bool, string) {

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
	p parameters.ParametersAccessor) http.Header {

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

func selectHostName(
	tunnelProtocol string, p parameters.ParametersAccessor) string {

	limitProtocols := p.TunnelProtocols(parameters.CustomHostNameLimitProtocols)
	if len(limitProtocols) > 0 && !common.Contains(limitProtocols, tunnelProtocol) {
		return values.GetHostName()
	}

	if !p.WeightedCoinFlip(parameters.CustomHostNameProbability) {
		return values.GetHostName()
	}

	regexStrings := p.RegexStrings(parameters.CustomHostNameRegexes)
	if len(regexStrings) == 0 {
		return values.GetHostName()
	}

	choice := prng.Intn(len(regexStrings))
	hostName, err := regen.Generate(regexStrings[choice])
	if err != nil {
		NoticeWarning("selectHostName: regen.Generate failed: %v", errors.Trace(err))
		return values.GetHostName()
	}

	return hostName
}
