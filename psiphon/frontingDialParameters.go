package psiphon

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
	utls "github.com/Psiphon-Labs/utls"
	"golang.org/x/net/bpf"
)

// FrontedMeekDialParameters represents a selected fronting transport and all
// the related protocol attributes, many chosen at random, for a fronted dial
// attempt.
//
// FrontedMeekDialParameters is used:
// - to configure dialers
// - as a persistent record to store successful dial parameters for replay
// - to report dial stats in notices and Psiphon API calls.
//
// FrontedMeekDialParameters is similar to tunnel DialParameters, but is
// specific to fronted meek. It should be used for all fronted meek dials,
// apart from the tunnel DialParameters cases.
//
// prepareDialConfigs must be called on any unmarshaled
// FrontedMeekDialParameters. For example, when unmarshaled from a replay
// record.
//
// resolvedIPAddress is set asynchronously, as it is not known until the dial
// process has begun. The atomic.Value will contain a string, initialized to
// "", and set to the resolved IP address once that part of the dial process
// has completed.
//
// FrontedMeekDialParameters is not safe for concurrent use.
type FrontedMeekDialParameters struct {
	NetworkLatencyMultiplier float64

	FrontingTransport string

	DialAddress string

	FrontingProviderID  string
	FrontingDialAddress string
	SNIServerName       string
	TransformedHostName bool
	VerifyServerName    string
	VerifyPins          []string
	HostHeader          string
	resolvedIPAddress   atomic.Value `json:"-"`

	TLSProfile               string
	TLSVersion               string
	RandomizedTLSProfileSeed *prng.Seed
	NoDefaultTLSSessionID    bool
	TLSFragmentClientHello   bool

	SelectedUserAgent bool
	UserAgent         string

	BPFProgramName         string
	BPFProgramInstructions []bpf.RawInstruction

	FragmentorSeed *prng.Seed

	ResolveParameters *resolver.ResolveParameters

	dialConfig *DialConfig `json:"-"`
	meekConfig *MeekConfig `json:"-"`
}

// makeFrontedMeekDialParameters creates a new FrontedMeekDialParameters for
// configuring a fronted HTTP client, including selecting a fronting transport,
// and all the various protocol attributes.
//
// payloadSecure must only be set if all HTTP plaintext payloads sent through
// the returned net/http.Client will be wrapped in their own transport security
// layer, which permits skipping of server certificate verification.
func makeFrontedMeekDialParameters(
	config *Config,
	p parameters.ParametersAccessor,
	tunnel *Tunnel,
	frontingSpecs parameters.FrontingSpecs,
	selectedFrontingProviderID func(string),
	useDeviceBinder,
	skipVerify,
	disableSystemRootCAs,
	payloadSecure bool,
	tlsCache utls.ClientSessionCache) (*FrontedMeekDialParameters, error) {

	// This function duplicates some code from MakeDialParameters. To simplify
	// the logic, the Replay<Component> tactic flags for individual dial
	// components are ignored.
	//
	// TODO: merge common functionality?

	if !payloadSecure && (skipVerify || disableSystemRootCAs) {
		return nil, errors.TraceNew("cannot skip certificate verification if payload insecure")
	}

	frontedMeekDialParams := FrontedMeekDialParameters{}

	// Network latency multiplier

	frontedMeekDialParams.NetworkLatencyMultiplier = prng.ExpFloat64Range(
		p.Float(parameters.NetworkLatencyMultiplierMin),
		p.Float(parameters.NetworkLatencyMultiplierMax),
		p.Float(parameters.NetworkLatencyMultiplierLambda))

	// Select fronting configuration

	var err error

	frontedMeekDialParams.FrontingProviderID,
		frontedMeekDialParams.FrontingTransport,
		frontedMeekDialParams.FrontingDialAddress,
		frontedMeekDialParams.SNIServerName,
		frontedMeekDialParams.VerifyServerName,
		frontedMeekDialParams.VerifyPins,
		frontedMeekDialParams.HostHeader,
		err = frontingSpecs.SelectParameters()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// At this time, the transport is limited to fronted HTTPS.
	//
	// As a future enhancement, allow HTTP in certain cases (e.g. the in-proxy
	// broker case), skip selecting TLS tactics and select HTTP tactics such as
	// HTTPTransformerParameters; and allow QUIC and select QUIC tactics.

	if frontedMeekDialParams.FrontingTransport != protocol.FRONTING_TRANSPORT_HTTPS {
		return nil, errors.TraceNew("unsupported fronting transport")
	}

	if selectedFrontingProviderID != nil {
		selectedFrontingProviderID(frontedMeekDialParams.FrontingProviderID)
	}

	// FrontingSpec.Addresses may include a port; default to 443 if none.

	if _, _, err := net.SplitHostPort(frontedMeekDialParams.FrontingDialAddress); err == nil {
		frontedMeekDialParams.DialAddress = frontedMeekDialParams.FrontingDialAddress
	} else {
		frontedMeekDialParams.DialAddress = net.JoinHostPort(frontedMeekDialParams.FrontingDialAddress, "443")
	}

	// Determine and use the equivalent tunnel protocol for tactics
	// selections. For example, for the broker transport FRONTED-HTTPS, use
	// the tactics for FRONTED-MEEK-OSSH.

	equivalentTunnelProtocol, err := protocol.EquivilentTunnelProtocol(frontedMeekDialParams.FrontingTransport)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// SNI configuration
	//
	// For a FrontingSpec, an SNI value of "" indicates to disable/omit SNI, so
	// never transform in that case.

	if frontedMeekDialParams.SNIServerName != "" {
		if p.WeightedCoinFlip(parameters.TransformHostNameProbability) {
			frontedMeekDialParams.SNIServerName = selectHostName(equivalentTunnelProtocol, p)
			frontedMeekDialParams.TransformedHostName = true
		}
	}

	// TLS configuration
	//
	// In the in-proxy case, the requireTLS13 flag is set to true, and
	// requireTLS12SessionTickets to false, in order to use only modern TLS
	// fingerprints which should support HTTP/2 in the ALPN.
	//
	// TODO: TLS padding

	requireTLS12SessionTickets :=
		!protocol.TunnelProtocolUsesInproxy(equivalentTunnelProtocol) &&
			protocol.TunnelProtocolRequiresTLS12SessionTickets(
				equivalentTunnelProtocol)

	requireTLS13Support :=
		protocol.TunnelProtocolUsesInproxy(equivalentTunnelProtocol) ||
			protocol.TunnelProtocolRequiresTLS13Support(equivalentTunnelProtocol)
	isFronted := true
	frontedMeekDialParams.TLSProfile,
		frontedMeekDialParams.TLSVersion,
		frontedMeekDialParams.RandomizedTLSProfileSeed,
		err = SelectTLSProfile(requireTLS12SessionTickets, requireTLS13Support, isFronted, frontedMeekDialParams.FrontingProviderID, p)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if frontedMeekDialParams.TLSProfile == "" && (requireTLS12SessionTickets || requireTLS13Support) {
		return nil, errors.TraceNew("required TLS profile not found")
	}

	frontedMeekDialParams.NoDefaultTLSSessionID = p.WeightedCoinFlip(
		parameters.NoDefaultTLSSessionIDProbability)

	if frontedMeekDialParams.SNIServerName != "" && net.ParseIP(frontedMeekDialParams.SNIServerName) == nil {
		tlsFragmentorLimitProtocols := p.TunnelProtocols(parameters.TLSFragmentClientHelloLimitProtocols)
		if len(tlsFragmentorLimitProtocols) == 0 || common.Contains(tlsFragmentorLimitProtocols, equivalentTunnelProtocol) {
			frontedMeekDialParams.TLSFragmentClientHello = p.WeightedCoinFlip(parameters.TLSFragmentClientHelloProbability)
		}
	}

	// User Agent configuration

	dialCustomHeaders := makeDialCustomHeaders(config, p)
	frontedMeekDialParams.SelectedUserAgent, frontedMeekDialParams.UserAgent = selectUserAgentIfUnset(p, dialCustomHeaders)

	// Resolver configuration
	//
	// The custom resolver is wired up only when there is a domain to be
	// resolved; GetMetrics will log resolver metrics when the resolver is set.

	if net.ParseIP(frontedMeekDialParams.DialAddress) == nil {

		resolver := config.GetResolver()
		if resolver == nil {
			return nil, errors.TraceNew("missing resolver")
		}

		frontedMeekDialParams.ResolveParameters, err = resolver.MakeResolveParameters(
			p, frontedMeekDialParams.FrontingProviderID, frontedMeekDialParams.DialAddress)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if tunnel == nil {

		// BPF configuration

		if ClientBPFEnabled() &&
			protocol.TunnelProtocolMayUseClientBPF(equivalentTunnelProtocol) {

			if p.WeightedCoinFlip(parameters.BPFClientTCPProbability) {
				frontedMeekDialParams.BPFProgramName = ""
				frontedMeekDialParams.BPFProgramInstructions = nil
				ok, name, rawInstructions := p.BPFProgram(parameters.BPFClientTCPProgram)
				if ok {
					frontedMeekDialParams.BPFProgramName = name
					frontedMeekDialParams.BPFProgramInstructions = rawInstructions
				}
			}
		}

		// Fragmentor configuration

		frontedMeekDialParams.FragmentorSeed, err = prng.NewSeed()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// Initialize Dial/MeekConfigs to be passed to the corresponding dialers.

	err = frontedMeekDialParams.prepareDialConfigs(
		config, p, tunnel, dialCustomHeaders, useDeviceBinder, skipVerify,
		disableSystemRootCAs, payloadSecure, tlsCache)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &frontedMeekDialParams, nil
}

// prepareDialConfigs is called for both new and replayed dial parameters.
func (f *FrontedMeekDialParameters) prepareDialConfigs(
	config *Config,
	p parameters.ParametersAccessor,
	tunnel *Tunnel,
	dialCustomHeaders http.Header,
	useDeviceBinder,
	skipVerify,
	disableSystemRootCAs,
	payloadSecure bool,
	tlsCache utls.ClientSessionCache) error {

	if !payloadSecure && (skipVerify || disableSystemRootCAs) {
		return errors.TraceNew("cannot skip certificate verification if payload insecure")
	}

	equivilentTunnelProtocol, err := protocol.EquivilentTunnelProtocol(f.FrontingTransport)
	if err != nil {
		return errors.Trace(err)
	}

	// Custom headers and User Agent

	if dialCustomHeaders == nil {
		dialCustomHeaders = makeDialCustomHeaders(config, p)
	}
	if f.SelectedUserAgent {
		dialCustomHeaders.Set("User-Agent", f.UserAgent)
	}

	// Fragmentor

	fragmentorConfig := fragmentor.NewUpstreamConfig(
		p, equivilentTunnelProtocol, f.FragmentorSeed)

	// Resolver
	//
	// DialConfig.ResolveIP is required and called even when the destination
	// is an IP address.

	resolver := config.GetResolver()
	if resolver == nil {
		return errors.TraceNew("missing resolver")
	}

	// DialConfig

	f.resolvedIPAddress.Store("")

	var resolveIP func(context.Context, string) ([]net.IP, error)
	if tunnel != nil {
		tunneledDialer := func(_, addr string) (net.Conn, error) {
			// Set alwaysTunneled to ensure the http.Client traffic is always tunneled,
			// even when split tunnel mode is enabled.
			conn, _, err := tunnel.DialTCPChannel(addr, true, nil)
			return conn, errors.Trace(err)
		}
		f.dialConfig = &DialConfig{
			DiagnosticID:                  f.FrontingProviderID,
			TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
			CustomDialer: func(_ context.Context, _, addr string) (net.Conn, error) {
				return tunneledDialer("", addr)
			},
		}
	} else {
		resolveIP = func(ctx context.Context, hostname string) ([]net.IP, error) {
			IPs, err := UntunneledResolveIP(
				ctx, config, resolver, hostname, f.FrontingProviderID)
			if err != nil {
				return nil, errors.Trace(err)
			}
			return IPs, nil
		}

		var deviceBinder DeviceBinder
		if useDeviceBinder {
			deviceBinder = config.DeviceBinder
		}

		f.dialConfig = &DialConfig{
			DiagnosticID:                  f.FrontingProviderID,
			UpstreamProxyURL:              config.UpstreamProxyURL,
			CustomHeaders:                 dialCustomHeaders,
			BPFProgramInstructions:        f.BPFProgramInstructions,
			TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
			FragmentorConfig:              fragmentorConfig,
			DeviceBinder:                  deviceBinder,
			IPv6Synthesizer:               config.IPv6Synthesizer,
			ResolveIP:                     resolveIP,
			ResolvedIPCallback: func(IPAddress string) {
				f.resolvedIPAddress.Store(IPAddress)
			},
		}
	}

	// MeekDialConfig

	// Note: if MeekModeRelay or MeekModeObfuscatedRoundTrip are supported in the
	// future, set MeekObfuscatorPaddingSeed.
	var meekMode MeekMode = MeekModePlaintextRoundTrip
	if payloadSecure {
		meekMode = MeekModeWrappedPlaintextRoundTrip
	}

	addFrontingHeader := addPsiphonFrontingHeader(
		p,
		f.FrontingProviderID,
		equivilentTunnelProtocol,
		f.DialAddress,
		f.ResolveParameters)

	f.meekConfig = &MeekConfig{
		DiagnosticID:             f.FrontingProviderID,
		Parameters:               config.GetParameters(),
		Mode:                     meekMode,
		DialAddress:              f.DialAddress,
		TLSProfile:               f.TLSProfile,
		TLSFragmentClientHello:   f.TLSFragmentClientHello,
		NoDefaultTLSSessionID:    f.NoDefaultTLSSessionID,
		RandomizedTLSProfileSeed: f.RandomizedTLSProfileSeed,
		SNIServerName:            f.SNIServerName,
		HostHeader:               f.HostHeader,
		TransformedHostName:      f.TransformedHostName,
		AddPsiphonFrontingHeader: addFrontingHeader,
		VerifyServerName:         f.VerifyServerName,
		VerifyPins:               f.VerifyPins,
		ClientTunnelProtocol:     equivilentTunnelProtocol,
		NetworkLatencyMultiplier: f.NetworkLatencyMultiplier,
		AdditionalHeaders:        config.MeekAdditionalHeaders,

		// CustomTLSDial will use the resolved IP address as the session key.
		TLSClientSessionCache: common.WrapUtlsClientSessionCache(tlsCache, common.TLS_NULL_SESSION_KEY),
	}

	if !skipVerify {
		f.meekConfig.DisableSystemRootCAs = disableSystemRootCAs
		if !f.meekConfig.DisableSystemRootCAs {
			f.meekConfig.VerifyServerName = f.VerifyServerName
			f.meekConfig.VerifyPins = f.VerifyPins
		}
	}

	switch f.FrontingTransport {
	case protocol.FRONTING_TRANSPORT_HTTPS:
		f.meekConfig.UseHTTPS = true
	case protocol.FRONTING_TRANSPORT_QUIC:
		// TODO: configure QUIC tactics
		f.meekConfig.UseQUIC = true
	}

	return nil
}

// GetMetrics returns log fields detailing the fronted meek dial parameters.
// All log field names are prefixed with overridePrefix, when specified, which
// also overrides any default prefixes.
func (meekDialParameters *FrontedMeekDialParameters) GetMetrics(overridePrefix string) common.LogFields {

	prefix := ""
	meekPrefix := "meek_"

	if overridePrefix != "" {
		prefix = overridePrefix
		meekPrefix = overridePrefix
	}

	logFields := make(common.LogFields)

	logFields[prefix+"fronting_provider_id"] = meekDialParameters.FrontingProviderID

	if meekDialParameters.DialAddress != "" {
		logFields[meekPrefix+"dial_address"] = meekDialParameters.DialAddress
	}

	meekResolvedIPAddress := meekDialParameters.resolvedIPAddress.Load().(string)
	if meekResolvedIPAddress != "" {
		logFields[meekPrefix+"resolved_ip_address"] = meekResolvedIPAddress
	}

	if meekDialParameters.SNIServerName != "" {
		logFields[meekPrefix+"sni_server_name"] = meekDialParameters.SNIServerName
	}

	if meekDialParameters.HostHeader != "" {
		logFields[meekPrefix+"host_header"] = meekDialParameters.HostHeader
	}

	transformedHostName := "0"
	if meekDialParameters.TransformedHostName {
		transformedHostName = "1"
	}
	logFields[meekPrefix+"transformed_host_name"] = transformedHostName

	if meekDialParameters.SelectedUserAgent {
		logFields[prefix+"user_agent"] = meekDialParameters.UserAgent
	}

	if meekDialParameters.FrontingTransport == protocol.FRONTING_TRANSPORT_HTTPS {

		if meekDialParameters.TLSProfile != "" {
			logFields[prefix+"tls_profile"] = meekDialParameters.TLSProfile
		}

		if meekDialParameters.TLSVersion != "" {
			logFields[prefix+"tls_version"] =
				getTLSVersionForMetrics(meekDialParameters.TLSVersion, meekDialParameters.NoDefaultTLSSessionID)
		}

		tlsFragmented := "0"
		if meekDialParameters.TLSFragmentClientHello {
			tlsFragmented = "1"
		}
		logFields[prefix+"tls_fragmented"] = tlsFragmented
	}

	if meekDialParameters.BPFProgramName != "" {
		logFields[prefix+"client_bpf"] = meekDialParameters.BPFProgramName
	}

	if meekDialParameters.ResolveParameters != nil {

		// See comment for dialParams.ResolveParameters handling in
		// getBaseAPIParameters.

		if meekDialParameters.ResolveParameters.PreresolvedIPAddress != "" {
			dialDomain, _, _ := net.SplitHostPort(meekDialParameters.meekConfig.DialAddress)
			if meekDialParameters.ResolveParameters.PreresolvedDomain == dialDomain {
				logFields[prefix+"dns_preresolved"] = meekDialParameters.ResolveParameters.PreresolvedIPAddress
			}
		}

		if meekDialParameters.ResolveParameters.PreferAlternateDNSServer {
			logFields[prefix+"dns_preferred"] = meekDialParameters.ResolveParameters.AlternateDNSServer
		}

		if meekDialParameters.ResolveParameters.ProtocolTransformName != "" {
			logFields[prefix+"dns_transform"] = meekDialParameters.ResolveParameters.ProtocolTransformName
		}

		if meekDialParameters.ResolveParameters.RandomQNameCasingSeed != nil {
			logFields[prefix+"dns_qname_random_casing"] = "1"
		}

		if meekDialParameters.ResolveParameters.ResponseQNameMustMatch {
			logFields[prefix+"dns_qname_must_match"] = "1"
		}

		logFields[prefix+"dns_qname_mismatches"] = strconv.Itoa(
			meekDialParameters.ResolveParameters.GetQNameMismatches())

		logFields[prefix+"dns_attempt"] = strconv.Itoa(
			meekDialParameters.ResolveParameters.GetFirstAttemptWithAnswer())
	}

	// TODO: get fragmentor metrics, if any, from MeekConn.

	return logFields
}
