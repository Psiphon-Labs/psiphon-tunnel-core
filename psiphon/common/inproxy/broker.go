/*
 * Copyright (c) 2023, Psiphon Inc.
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

package inproxy

import (
	"context"
	std_errors "errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/consistent"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/cespare/xxhash"
	lrucache "github.com/cognusion/go-cache-lru"
	"github.com/fxamacker/cbor/v2"
)

const (

	// BrokerMaxRequestBodySize is the maximum request size, that should be
	// enforced by the provided broker transport.
	BrokerMaxRequestBodySize = 65536

	// BrokerEndPointName is the standard name for referencing an endpoint
	// that services broker requests.
	BrokerEndPointName = "inproxy-broker"

	brokerProxyAnnounceTimeout        = 2 * time.Minute
	brokerClientOfferTimeout          = 10 * time.Second
	brokerPendingServerReportsTTL     = 60 * time.Second
	brokerPendingServerReportsMaxSize = 100000
	brokerMetricName                  = "inproxy_broker"
)

// LookupGeoIP is a callback for providing GeoIP lookup service.
type LookupGeoIP func(IP string) common.GeoIPData

// ExtendTransportTimeout is a callback that extends the timeout for a
// server-side broker transport handler, facilitating request-specific
// timeouts including long-polling for proxy announcements.
type ExtendTransportTimeout func(timeout time.Duration)

// GetTacticsPayload is a callback which returns the appropriate tactics
// payload for the specified client/proxy GeoIP data and API parameters.
type GetTacticsPayload func(
	common.GeoIPData, common.APIParameters) ([]byte, string, error)

// Broker is the in-proxy broker component, which matches clients and proxies
// and provides WebRTC signaling functionalty.
//
// Both clients and proxies send requests to the broker to obtain matches and
// exchange WebRTC SDPs. Broker does not implement a transport or obfuscation
// layer; instead that is provided by the HandleSessionPacket caller. A
// typical implementation would provide a domain fronted web server which
// runs a Broker and calls Broker.HandleSessionPacket to handle web requests
// encapsulating secure session packets.
type Broker struct {
	config                  *BrokerConfig
	brokerID                ID
	initiatorSessions       *InitiatorSessions
	responderSessions       *ResponderSessions
	matcher                 *Matcher
	pendingServerReports    *lrucache.Cache
	proxyQualityState       *ProxyQualityState
	knownServerInitiatorIDs sync.Map

	commonCompartmentsMutex sync.Mutex
	commonCompartments      *consistent.Consistent

	proxyAnnounceTimeout       int64
	clientOfferTimeout         int64
	clientOfferPersonalTimeout int64
	pendingServerReportsTTL    int64
	maxRequestTimeouts         atomic.Value
	maxCompartmentIDs          int64

	enableProxyQualityMutex sync.Mutex
	enableProxyQuality      atomic.Bool
}

// BrokerConfig specifies the configuration for a Broker.
type BrokerConfig struct {

	// Logger is used to log events.
	Logger common.Logger

	// CommonCompartmentIDs is a list of common compartment IDs to apply to
	// proxies that announce without personal compartment ID. Common
	// compartment IDs are managed by Psiphon and distributed to clients via
	// tactics or embedded in OSLs. Clients must supply a valid compartment
	// ID to match with a proxy.
	//
	// A BrokerConfig must supply at least one compartment ID, or
	// SetCompartmentIDs must be called with at least one compartment ID
	// before calling Start.
	//
	// When only one, single common compartment ID is configured, it can serve
	// as an (obfuscation) secret that clients must obtain, via tactics, to
	// enable in-proxy participation.
	CommonCompartmentIDs []ID

	// AllowProxy is a callback which can indicate whether a proxy with the
	// given GeoIP data is allowed to match with common compartment ID
	// clients. Proxies with personal compartment IDs are always allowed.
	AllowProxy func(common.GeoIPData) bool

	// PrioritizeProxy is a callback which can indicate whether proxy
	// announcements from proxies with the specified in-proxy protocol
	// version, GeoIPData, and APIParameters should be prioritized in the
	// matcher queue. Priority proxy announcements match ahead of other proxy
	// announcements, regardless of announcement age/deadline. Priority
	// status takes precedence over preferred NAT matching. Prioritization
	// applies only to common compartment IDs and not personal pairing mode.
	PrioritizeProxy func(int, common.GeoIPData, common.APIParameters) bool

	// AllowClient is a callback which can indicate whether a client with the
	// given GeoIP data is allowed to match with common compartment ID
	// proxies. Clients are always allowed to match based on personal
	// compartment ID.
	AllowClient func(common.GeoIPData) bool

	// AllowDomainFrontedDestinations is a callback which can indicate whether
	// a client with the given GeoIP data is allowed to specify a proxied
	// destination for a domain fronted protocol. When false, only direct
	// address destinations are allowed.
	//
	// While tactics may may be set to instruct clients to use only direct
	// server tunnel protocols, with IP address destinations, this callback
	// adds server-side enforcement.
	AllowDomainFrontedDestinations func(common.GeoIPData) bool

	// AllowMatch is a callback which can indicate whether a proxy and client
	// pair, with the given, respective GeoIP data, is allowed to match
	// together. Pairs are always allowed to match based on personal
	// compartment ID.
	AllowMatch func(common.GeoIPData, common.GeoIPData) bool

	// LookupGeoIP provides GeoIP lookup service.
	LookupGeoIP LookupGeoIP

	// APIParameterValidator is a callback that validates base API metrics.
	APIParameterValidator common.APIParameterValidator

	// APIParameterValidator is a callback that formats base API metrics.
	APIParameterLogFieldFormatter common.APIParameterLogFieldFormatter

	// GetTacticsPayload provides a tactics lookup service.
	GetTacticsPayload GetTacticsPayload

	// IsValidServerEntryTag is a callback which checks if the specified
	// server entry tag is on the list of valid and active Psiphon server
	// entry tags.
	IsValidServerEntryTag func(serverEntryTag string) bool

	// IsLoadLimiting is a callback which checks if the broker process is in a
	// load limiting state, where consumed resources, including allocated
	// system memory and CPU load, exceed determined thresholds. When load
	// limiting is indicated, the broker will attempt to reduce load by
	// immediately rejecting either proxy announces or client offers,
	// depending on the state of the corresponding queues.
	IsLoadLimiting func() bool

	// PrivateKey is the broker's secure session long term private key.
	PrivateKey SessionPrivateKey

	// ObfuscationRootSecret broker's secure session long term obfuscation key.
	ObfuscationRootSecret ObfuscationSecret

	// ServerEntrySignaturePublicKey is the key used to verify Psiphon server
	// entry signatures.
	ServerEntrySignaturePublicKey string

	// These timeout parameters may be used to override defaults.
	ProxyAnnounceTimeout       time.Duration
	ClientOfferTimeout         time.Duration
	ClientOfferPersonalTimeout time.Duration
	PendingServerReportsTTL    time.Duration

	// Announcement queue limit configuration.
	MatcherAnnouncementLimitEntryCount    int
	MatcherAnnouncementRateLimitQuantity  int
	MatcherAnnouncementRateLimitInterval  time.Duration
	MatcherAnnouncementNonlimitedProxyIDs []ID

	// Offer queue limit configuration.
	MatcherOfferLimitEntryCount   int
	MatcherOfferRateLimitQuantity int
	MatcherOfferRateLimitInterval time.Duration

	// MaxCompartmentIDs specifies the maximum number of compartment IDs that
	// can be included, per list, in one request. If 0, the value
	// MaxCompartmentIDs is used.
	MaxCompartmentIDs int
}

// NewBroker initializes a new Broker.
func NewBroker(config *BrokerConfig) (*Broker, error) {

	// initiatorSessions are secure sessions initiated by the broker and used
	// to send BrokerServerReports to servers. The servers will be
	// configured to establish sessions only with brokers with specified
	// public keys.

	initiatorSessions := NewInitiatorSessions(config.PrivateKey)

	// responderSessions are secure sessions initiated by clients and proxies
	// and used to send requests to the broker. Clients and proxies are
	// configured to establish sessions only with specified broker public keys.

	responderSessions, err := NewResponderSessions(
		config.PrivateKey, config.ObfuscationRootSecret)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The broker ID is the broker's session public key in Curve25519 form.
	publicKey, err := config.PrivateKey.GetPublicKey()
	if err != nil {
		return nil, errors.Trace(err)
	}
	brokerID, err := publicKey.ToCurve25519()
	if err != nil {
		return nil, errors.Trace(err)
	}

	proxyQuality := NewProxyQuality()

	b := &Broker{
		config:            config,
		brokerID:          ID(brokerID),
		initiatorSessions: initiatorSessions,
		responderSessions: responderSessions,
		matcher: NewMatcher(&MatcherConfig{
			Logger: config.Logger,

			AnnouncementLimitEntryCount:    config.MatcherAnnouncementLimitEntryCount,
			AnnouncementRateLimitQuantity:  config.MatcherAnnouncementRateLimitQuantity,
			AnnouncementRateLimitInterval:  config.MatcherAnnouncementRateLimitInterval,
			AnnouncementNonlimitedProxyIDs: config.MatcherAnnouncementNonlimitedProxyIDs,

			OfferLimitEntryCount:   config.MatcherOfferLimitEntryCount,
			OfferRateLimitQuantity: config.MatcherOfferRateLimitQuantity,
			OfferRateLimitInterval: config.MatcherOfferRateLimitInterval,

			ProxyQualityState: proxyQuality,

			IsLoadLimiting: config.IsLoadLimiting,

			AllowMatch: config.AllowMatch,
		}),

		proxyQualityState: proxyQuality,

		proxyAnnounceTimeout:       int64(config.ProxyAnnounceTimeout),
		clientOfferTimeout:         int64(config.ClientOfferTimeout),
		clientOfferPersonalTimeout: int64(config.ClientOfferPersonalTimeout),
		pendingServerReportsTTL:    int64(config.PendingServerReportsTTL),

		maxCompartmentIDs: int64(common.ValueOrDefault(config.MaxCompartmentIDs, MaxCompartmentIDs)),
	}

	b.pendingServerReports = lrucache.NewWithLRU(
		common.ValueOrDefault(config.PendingServerReportsTTL, brokerPendingServerReportsTTL),
		1*time.Minute,
		brokerPendingServerReportsMaxSize)

	if len(config.CommonCompartmentIDs) > 0 {
		err = b.initializeCommonCompartmentIDHashing(config.CommonCompartmentIDs)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	return b, nil
}

func (b *Broker) Start() error {

	if !b.isCommonCompartmentIDHashingInitialized() {
		return errors.TraceNew("missing common compartment IDs")
	}

	return errors.Trace(b.matcher.Start())
}

func (b *Broker) Stop() {
	b.matcher.Stop()
}

// SetCommonCompartmentIDs sets a new list of common compartment IDs,
// replacing the previous configuration.
func (b *Broker) SetCommonCompartmentIDs(commonCompartmentIDs []ID) error {

	// TODO: initializeCommonCompartmentIDHashing is called regardless whether
	// commonCompartmentIDs changes the previous configuration. To avoid the
	// overhead of consistent hashing initialization in
	// initializeCommonCompartmentIDHashing, add a mechanism to first quickly
	// check for changes?

	return errors.Trace(b.initializeCommonCompartmentIDHashing(commonCompartmentIDs))
}

// SetTimeouts sets new timeout values, replacing the previous configuration.
// New timeout values do not apply to currently active announcement or offer
// requests.
func (b *Broker) SetTimeouts(
	proxyAnnounceTimeout time.Duration,
	clientOfferTimeout time.Duration,
	clientOfferPersonalTimeout time.Duration,
	pendingServerReportsTTL time.Duration,
	maxRequestTimeouts map[string]time.Duration) {

	atomic.StoreInt64(&b.proxyAnnounceTimeout, int64(proxyAnnounceTimeout))
	atomic.StoreInt64(&b.clientOfferTimeout, int64(clientOfferTimeout))
	atomic.StoreInt64(&b.clientOfferPersonalTimeout, int64(clientOfferPersonalTimeout))
	atomic.StoreInt64(&b.pendingServerReportsTTL, int64(pendingServerReportsTTL))
	b.maxRequestTimeouts.Store(maxRequestTimeouts)
}

// SetLimits sets new queue limit values, replacing the previous
// configuration. New limits are only partially applied to existing queue
// states; see Matcher.SetLimits.
func (b *Broker) SetLimits(
	matcherAnnouncementLimitEntryCount int,
	matcherAnnouncementRateLimitQuantity int,
	matcherAnnouncementRateLimitInterval time.Duration,
	matcherAnnouncementNonlimitedProxyIDs []ID,
	matcherOfferLimitEntryCount int,
	matcherOfferRateLimitQuantity int,
	matcherOfferRateLimitInterval time.Duration,
	maxCompartmentIDs int) {

	b.matcher.SetLimits(
		matcherAnnouncementLimitEntryCount,
		matcherAnnouncementRateLimitQuantity,
		matcherAnnouncementRateLimitInterval,
		matcherAnnouncementNonlimitedProxyIDs,
		matcherOfferLimitEntryCount,
		matcherOfferRateLimitQuantity,
		matcherOfferRateLimitInterval)

	atomic.StoreInt64(
		&b.maxCompartmentIDs,
		int64(common.ValueOrDefault(maxCompartmentIDs, MaxCompartmentIDs)))
}

func (b *Broker) SetProxyQualityParameters(
	enable bool,
	qualityTTL time.Duration,
	pendingFailedMatchDeadline time.Duration,
	failedMatchThreshold int) {

	// enableProxyQuality is an atomic for fast lookups in request handlers;
	// an additional mutex is used here to ensure the Swap/Flush combination
	// is also atomic.
	b.enableProxyQualityMutex.Lock()
	wasEnabled := b.enableProxyQuality.Swap(enable)
	if wasEnabled && !enable {
		// Flush quality state, since otherwise the quality TTL can retain
		// quality data which may be unexpectedly reactivated when enable is
		// toggled on again.
		b.proxyQualityState.Flush()
	}
	b.enableProxyQualityMutex.Unlock()

	b.proxyQualityState.SetParameters(
		qualityTTL,
		pendingFailedMatchDeadline,
		failedMatchThreshold)
}

// HandleSessionPacket handles a session packet from a client or proxy and
// provides a response packet. The packet is part of a secure session and may
// be a session handshake message, an expired session reset token, or a
// session-wrapped request payload. Request payloads are routed to API
// request endpoints.
//
// The caller is expected to provide a transport obfuscation layer, such as
// domain fronted HTTPs. The session has an obfuscation layer that ensures
// that packets are fully random, randomly padded, and cannot be replayed.
// This makes session packets suitable to embed as plaintext in some
// transports.
//
// The caller is responsible for rate limiting and enforcing timeouts and
// maximum payload size checks.
//
// Secure sessions support multiplexing concurrent requests, as long as the
// provided transport, for example HTTP/2, supports this as well.
//
// The input ctx should be canceled if the client/proxy disconnects from the
// transport while HandleSessionPacket is running, since long-polling proxy
// announcement requests will otherwise remain blocked until eventual
// timeout; net/http does this.
//
// When HandleSessionPacket returns an error, the transport provider should
// apply anti-probing mechanisms, as the client/proxy may be a prober or
// scanner.
func (b *Broker) HandleSessionPacket(
	ctx context.Context,
	extendTransportTimeout ExtendTransportTimeout,
	transportLogFields common.LogFields,
	brokerClientIP string,
	geoIPData common.GeoIPData,
	inPacket []byte) ([]byte, error) {

	// handleUnwrappedRequest handles requests after session unwrapping.
	// responderSessions.HandlePacket handles both session establishment and
	// request unwrapping, and invokes handleUnwrappedRequest once a session
	// is established and a valid request unwrapped.

	handleUnwrappedRequest := func(initiatorID ID, unwrappedRequestPayload []byte) ([]byte, error) {

		recordType, err := peekRecordPreambleType(unwrappedRequestPayload)
		if err != nil {
			return nil, errors.Trace(err)
		}

		var responsePayload []byte

		switch recordType {
		case recordTypeAPIProxyAnnounceRequest:
			responsePayload, err = b.handleProxyAnnounce(
				ctx,
				extendTransportTimeout,
				transportLogFields,
				brokerClientIP,
				geoIPData,
				initiatorID,
				unwrappedRequestPayload)
			if err != nil {
				return nil, errors.Trace(err)
			}
		case recordTypeAPIProxyAnswerRequest:
			responsePayload, err = b.handleProxyAnswer(
				ctx,
				extendTransportTimeout,
				transportLogFields,
				brokerClientIP,
				geoIPData,
				initiatorID,
				unwrappedRequestPayload)
			if err != nil {
				return nil, errors.Trace(err)
			}
		case recordTypeAPIClientOfferRequest:
			responsePayload, err = b.handleClientOffer(
				ctx,
				extendTransportTimeout,
				transportLogFields,
				brokerClientIP,
				geoIPData,
				initiatorID,
				unwrappedRequestPayload)
			if err != nil {
				return nil, errors.Trace(err)
			}
		case recordTypeAPIServerProxyQualityRequest:
			responsePayload, err = b.handleServerProxyQuality(
				ctx,
				extendTransportTimeout,
				transportLogFields,
				brokerClientIP,
				geoIPData,
				initiatorID,
				unwrappedRequestPayload)
			if err != nil {
				return nil, errors.Trace(err)
			}
		case recordTypeAPIClientRelayedPacketRequest:
			responsePayload, err = b.handleClientRelayedPacket(
				ctx,
				extendTransportTimeout,
				transportLogFields,
				geoIPData,
				initiatorID,
				unwrappedRequestPayload)
			if err != nil {
				return nil, errors.Trace(err)
			}
		default:
			return nil, errors.Tracef("unexpected API record type %v", recordType)
		}

		return responsePayload, nil

	}

	// HandlePacket returns both a packet and an error in the expired session
	// reset token case. Log the error here, clear it, and return the
	// packet to be relayed back to the broker client.

	outPacket, err := b.responderSessions.HandlePacket(
		inPacket, handleUnwrappedRequest)
	if err != nil {
		if outPacket == nil {
			return nil, errors.Trace(err)
		}
		b.config.Logger.WithTraceFields(common.LogFields{"error": err}).Warning(
			"HandlePacket returned packet and error")
	}
	return outPacket, nil
}

// handleProxyAnnounce receives a proxy announcement, awaits a matching
// client, and returns the client offer in the response. handleProxyAnnounce
// has a long timeout so this request can idle until a matching client
// arrives.
func (b *Broker) handleProxyAnnounce(
	ctx context.Context,
	extendTransportTimeout ExtendTransportTimeout,
	transportLogFields common.LogFields,
	proxyIP string,
	geoIPData common.GeoIPData,
	initiatorID ID,
	requestPayload []byte) (retResponse []byte, retErr error) {

	startTime := time.Now()

	var logFields common.LogFields
	var isPriority bool
	var newTacticsTag string
	var clientOffer *MatchOffer
	var matchMetrics *MatchMetrics
	var timedOut bool
	var limitedErr error

	// As a future enhancement, a broker could initiate its own test
	// connection to the proxy to verify its effectiveness, including
	// simulating a symmetric NAT client.

	// Each announcement represents availability for a single client matching.
	// Proxies with multiple client availability will send multiple requests.
	//
	// The announcement request and response could be extended to allow the
	// proxy to specify availability for multiple clients in the request, and
	// multiple client offers returned in the response.
	//
	// If, as we expect, proxies run on home ISPs have limited upstream
	// bandwidth, they will support only a couple of concurrent clients, and
	// the simple single-client-announcment model may be sufficient. Also, if
	// the transport is HTTP/2, multiple requests can be multiplexed over a
	// single connection (and session) in any case.

	// The proxy ID is an implicit parameter: it's the proxy's session public
	// key. As part of the session handshake, the proxy has proven that it
	// has the corresponding private key. Proxy IDs are logged to attribute
	// traffic to a specific proxy.

	proxyID := initiatorID

	// Generate a connection ID. This ID is used to associate proxy
	// announcments, client offers, and proxy answers, as well as associating
	// Psiphon tunnels with in-proxy pairings.
	connectionID, err := MakeID()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Always log the outcome.
	defer func() {
		if logFields == nil {
			logFields = b.config.APIParameterLogFieldFormatter("", geoIPData, nil)
		}
		logFields["broker_event"] = "proxy-announce"
		logFields["broker_id"] = b.brokerID
		logFields["proxy_id"] = proxyID
		logFields["is_priority"] = isPriority
		logFields["elapsed_time"] = time.Since(startTime) / time.Millisecond
		logFields["connection_id"] = connectionID
		if newTacticsTag != "" {
			logFields["new_tactics_tag"] = newTacticsTag
		}
		if clientOffer != nil {
			// Log the target Psiphon server ID (diagnostic ID). The presence
			// of this field indicates that a match was made.
			logFields["destination_server_id"] = clientOffer.DestinationServerID
			logFields["use_media_streams"] = clientOffer.UseMediaStreams
		}
		if timedOut {
			logFields["timed_out"] = true
		}
		if retErr != nil {
			logFields["error"] = retErr.Error()
		} else if limitedErr != nil {
			logFields["error"] = limitedErr.Error()
		}
		logFields.Add(transportLogFields)
		logFields.Add(matchMetrics.GetMetrics())
		b.config.Logger.LogMetric(brokerMetricName, logFields)
	}()

	announceRequest, err := UnmarshalProxyAnnounceRequest(requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var apiParams common.APIParameters
	apiParams, logFields, err = announceRequest.ValidateAndGetParametersAndLogFields(
		int(atomic.LoadInt64(&b.maxCompartmentIDs)),
		b.config.APIParameterValidator,
		b.config.APIParameterLogFieldFormatter,
		geoIPData)
	if err != nil {
		return nil, errors.Trace(err)
	}

	hasPersonalCompartmentIDs := len(announceRequest.PersonalCompartmentIDs) > 0

	// Return MustUpgrade when the proxy's protocol version is less than the
	// minimum required.
	if announceRequest.Metrics.ProtocolVersion < minimumProxyProtocolVersion {
		responsePayload, err := MarshalProxyAnnounceResponse(
			&ProxyAnnounceResponse{
				NoMatch:     true,
				MustUpgrade: true,
			})
		if err != nil {
			return nil, errors.Trace(err)
		}

		return responsePayload, nil

	}

	// Fetch new tactics for the proxy, if required, using the tactics tag
	// that should be included with the API parameters. A tacticsPayload may
	// be returned when there are no new tactics, and this is relayed back to
	// the proxy, after matching, so that it can extend the TTL for its
	// existing, cached tactics. In the case where tactics have changed,
	// don't enqueue the proxy announcement and return no-match so that the
	// proxy can store and apply the new tactics before announcing again.

	var tacticsPayload []byte
	if announceRequest.CheckTactics {
		tacticsPayload, newTacticsTag, err =
			b.config.GetTacticsPayload(geoIPData, apiParams)
		if err != nil {
			return nil, errors.Trace(err)
		}

		if tacticsPayload != nil && newTacticsTag != "" {
			responsePayload, err := MarshalProxyAnnounceResponse(
				&ProxyAnnounceResponse{
					TacticsPayload: tacticsPayload,
					NoMatch:        true,
				})
			if err != nil {
				return nil, errors.Trace(err)
			}

			return responsePayload, nil
		}
	}

	// AllowProxy may be used to disallow proxies from certain geolocations,
	// such as censored locations, from announcing. Proxies with personal
	// compartment IDs are always allowed, as they will be used only by
	// clients specifically configured to use them.

	if !hasPersonalCompartmentIDs &&
		!b.config.AllowProxy(geoIPData) {

		return nil, errors.TraceNew("proxy disallowed")
	}

	// Assign this proxy to a common compartment ID, unless it has specified a
	// dedicated, personal compartment ID. Assignment uses consistent hashing
	// keyed with the proxy ID, in an effort to keep proxies consistently
	// assigned to the same compartment.

	var commonCompartmentIDs []ID
	if !hasPersonalCompartmentIDs {
		compartmentID, err := b.selectCommonCompartmentID(proxyID)
		if err != nil {
			return nil, errors.Trace(err)
		}
		commonCompartmentIDs = []ID{compartmentID}
	}

	// Determine whether to enqueue the proxy announcement in the priority
	// queue. To be prioritized, a proxy, identified by its ID and ASN, must
	// have a recent quality tunnel recorded in the quality state. In
	// addition, when the PrioritizeProxy callback is set, invoke this
	// additional condition, which can filter by proxy geolocation and other
	// properties.
	//
	// There is no prioritization for personal pairing announcements.

	// Potential future enhancements:
	//
	// - For a proxy with unknown quality (neither reported quality tunnels,
	//   nor known failed matches), prioritize with some low probability to
	//   give unknown proxies a chance to qualify? This could be limited, for
	//   example, to proxies in the same ASN as other quality proxies. To
	//   implement this, ProxyQualityState would need to record proxy IDs
	//   with failed matches; and proxy ASNs would need to be input to
	//   ProxyQualityState.
	//
	// - Consider using the Psiphon server region, as given in the signed
	//   server entry, as part of the prioritization logic.

	if !hasPersonalCompartmentIDs && b.enableProxyQuality.Load() {

		// Here, no specific client ASN is specified for HasQuality. As long
		// as a proxy has a quality tunnel for any client ASN, it is
		// prioritized. In the matching process, an attempt is made to match
		// using HasQuality using the client ASN. See Matcher.matchOffer.

		isPriority = b.proxyQualityState.HasQuality(proxyID, geoIPData.ASN, "")
	}

	if isPriority && b.config.PrioritizeProxy != nil {

		// Note that, in the psiphon/server package, inproxyBrokerPrioritizeProxy
		// is always wired up, and, as currently implemented, the default value for
		// the InproxyBrokerMatcherPrioritizeProxiesFilter tactics parameter
		// results in PrioritizeProxy always returning false. Some filter,
		// even just a wildcard match, must be configured in order to prioritize.

		// Limitation: Of the two return values from
		// ValidateAndGetParametersAndLogFields, apiParams and logFields,
		// only logFields contains fields such as max_clients
		// and *_bytes_per_second, and so these cannot be part of any
		// filtering performed by the PrioritizeProxy callback.
		//
		// TODO: include the additional fields in logFields. Since the
		// logFields return value is the output of server.getRequestLogFields
		// processing, it's not safe to use it directly. In addition,
		// filtering by fields such as max_clients and *_bytes_per_second
		// calls for range filtering, which is not yet supported in the
		// psiphon/server.MeekServer PrioritizeProxy provider.

		isPriority = b.config.PrioritizeProxy(
			int(announceRequest.Metrics.ProtocolVersion), geoIPData, apiParams)
	}

	// Await client offer.

	timeout := common.ValueOrDefault(
		time.Duration(atomic.LoadInt64(&b.proxyAnnounceTimeout)),
		brokerProxyAnnounceTimeout)

	// Adjust the timeout to respect any shorter maximum request timeouts for
	// the fronting provider.
	timeout = b.adjustRequestTimeout(logFields, timeout)

	announceCtx, cancelFunc := context.WithTimeout(ctx, timeout)
	defer cancelFunc()
	extendTransportTimeout(timeout)

	// Note that matcher.Announce assumes a monotonically increasing
	// announceCtx.Deadline input for each successive call.

	clientOffer, matchMetrics, err = b.matcher.Announce(
		announceCtx,
		proxyIP,
		&MatchAnnouncement{
			Properties: MatchProperties{
				IsPriority:             isPriority,
				ProtocolVersion:        announceRequest.Metrics.ProtocolVersion,
				CommonCompartmentIDs:   commonCompartmentIDs,
				PersonalCompartmentIDs: announceRequest.PersonalCompartmentIDs,
				GeoIPData:              geoIPData,
				NetworkType:            GetNetworkType(announceRequest.Metrics.BaseAPIParameters),
				NATType:                announceRequest.Metrics.NATType,
				PortMappingTypes:       announceRequest.Metrics.PortMappingTypes,
			},
			ProxyID:      initiatorID,
			ProxyMetrics: announceRequest.Metrics,
			ConnectionID: connectionID,
		})
	if err != nil {

		var limitError *MatcherLimitError
		limited := std_errors.As(err, &limitError)

		timeout := announceCtx.Err() == context.DeadlineExceeded

		if !limited && !timeout {
			return nil, errors.Trace(err)
		}

		// A no-match response is sent in the case of a timeout awaiting a
		// match. The faster-failing rate or entry limiting case also results
		// in a response, rather than an error return from handleProxyAnnounce,
		// so that the proxy doesn't receive a 404 and flag its BrokerClient as
		// having failed.
		//
		// When the timeout and limit case coincide, limit takes precedence in
		// the response.

		if timeout && !limited {

			// Note: the respective proxy and broker timeouts,
			// InproxyBrokerProxyAnnounceTimeout and
			// InproxyProxyAnnounceRequestTimeout in tactics, should be
			// configured so that the broker will timeout first and have an
			// opportunity to send this response before the proxy times out.

			timedOut = true

		} else {

			// Record the specific limit error in the proxy-announce broker event.

			limitedErr = err
		}

		responsePayload, err := MarshalProxyAnnounceResponse(
			&ProxyAnnounceResponse{
				TacticsPayload: tacticsPayload,
				Limited:        limited,
				NoMatch:        timeout && !limited,
			})
		if err != nil {
			return nil, errors.Trace(err)
		}

		return responsePayload, nil
	}

	// Select the protocol version. The matcher has already checked
	// negotiateProtocolVersion, so failure is not expected.

	negotiatedProtocolVersion, ok := negotiateProtocolVersion(
		announceRequest.Metrics.ProtocolVersion,
		clientOffer.Properties.ProtocolVersion,
		clientOffer.UseMediaStreams)
	if !ok {
		return nil, errors.TraceNew("unexpected negotiateProtocolVersion failure")
	}

	// Respond with the client offer. The proxy will follow up with an answer
	// request, which is relayed to the client, and then the WebRTC dial begins.

	// Limitation: as part of the client's tunnel establishment horse race, a
	// client may abort an in-proxy dial at any point. If the overall dial is
	// past the SDP exchange and aborted during the WebRTC connection
	// establishment, the client may leave the proxy's Proxy.proxyOneClient
	// dangling until timeout. Consider adding a signal from the client to
	// the proxy, relayed by the broker, that a dial is aborted.

	responsePayload, err := MarshalProxyAnnounceResponse(
		&ProxyAnnounceResponse{
			TacticsPayload:              tacticsPayload,
			ConnectionID:                connectionID,
			SelectedProtocolVersion:     negotiatedProtocolVersion,
			ClientOfferSDP:              clientOffer.ClientOfferSDP,
			ClientRootObfuscationSecret: clientOffer.ClientRootObfuscationSecret,
			DoDTLSRandomization:         clientOffer.DoDTLSRandomization,
			UseMediaStreams:             clientOffer.UseMediaStreams,
			TrafficShapingParameters:    clientOffer.TrafficShapingParameters,
			NetworkProtocol:             clientOffer.NetworkProtocol,
			DestinationAddress:          clientOffer.DestinationAddress,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Set the "failed match" trigger, which will progress towards clearing
	// the quality state for this proxyID unless quality tunnels are reported
	// soon enough after matches. This includes failure, by the proxy, to
	// return an proxy answer, as well as any tunnel failures after that.
	//
	// Failures are expected even for good quality proxies, due to cases such
	// as the in-proxy protocol losing the client tunnel establishment horse
	// race. There is a threshold number of failed matches that must be
	// reached before a quality state is cleared.

	b.proxyQualityState.Matched(proxyID, geoIPData.ASN)

	return responsePayload, nil
}

// handleClientOffer receives a client offer, awaits a matching client, and
// returns the proxy answer. handleClientOffer has a shorter timeout than
// handleProxyAnnounce since the client has supplied an SDP with STUN hole
// punches which will expire; and, in general, the client is trying to
// connect immediately and is also trying other candidates.
func (b *Broker) handleClientOffer(
	ctx context.Context,
	extendTransportTimeout ExtendTransportTimeout,
	transportLogFields common.LogFields,
	clientIP string,
	geoIPData common.GeoIPData,
	initiatorID ID,
	requestPayload []byte) (retResponse []byte, retErr error) {

	// As a future enhancement, consider having proxies send offer SDPs with
	// announcements and clients long poll to await a match and then provide
	// an answer. This order of operations would make sense if client demand
	// is high and proxy supply is lower.
	//
	// Also see comment in Proxy.proxyOneClient for other alternative
	// approaches.

	// The client's session public key is ephemeral and is not logged.

	startTime := time.Now()

	var logFields common.LogFields
	var serverParams *serverParams
	var clientMatchOffer *MatchOffer
	var proxyMatchAnnouncement *MatchAnnouncement
	var proxyAnswer *MatchAnswer
	var matchMetrics *MatchMetrics
	var timedOut bool
	var limitedErr error

	// Always log the outcome.
	defer func() {
		if logFields == nil {
			logFields = b.config.APIParameterLogFieldFormatter("", geoIPData, nil)
		}
		logFields["broker_event"] = "client-offer"
		logFields["broker_id"] = b.brokerID
		if serverParams != nil {
			logFields["destination_server_id"] = serverParams.serverID
		}
		logFields["elapsed_time"] = time.Since(startTime) / time.Millisecond
		if proxyAnswer != nil {

			// The presence of these fields indicate that a match was made,
			// the proxy delivered an answer, and the client was still
			// waiting for it.

			logFields["connection_id"] = proxyAnswer.ConnectionID
			logFields["client_nat_type"] = clientMatchOffer.Properties.NATType
			logFields["client_port_mapping_types"] = clientMatchOffer.Properties.PortMappingTypes
			logFields["proxy_nat_type"] = proxyMatchAnnouncement.Properties.NATType
			logFields["proxy_port_mapping_types"] = proxyMatchAnnouncement.Properties.PortMappingTypes
			logFields["preferred_nat_match"] =
				clientMatchOffer.Properties.IsPreferredNATMatch(&proxyMatchAnnouncement.Properties)

			// TODO: also log proxy ice_candidate_types and has_IPv6; for the
			// client, these values are added by ValidateAndGetLogFields.
		}
		if timedOut {
			logFields["timed_out"] = true
		}
		if retErr != nil {
			logFields["error"] = retErr.Error()
		} else if limitedErr != nil {
			logFields["error"] = limitedErr.Error()
		}
		logFields.Add(transportLogFields)
		logFields.Add(matchMetrics.GetMetrics())
		b.config.Logger.LogMetric(brokerMetricName, logFields)
	}()

	offerRequest, err := UnmarshalClientOfferRequest(requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The filtered SDP is the request SDP with any invalid (bogon, unexpected
	// GeoIP) ICE candidates filtered out. In some cases, clients cannot
	// avoid submitting invalid candidates (see comment in
	// processSDPAddresses), so all invalid candidates are removed and the
	// remaining SDP is used. Filtered candidate information is logged in
	// logFields.
	//
	// In personal pairing mode, RFC 1918/4193 private IP addresses are
	// permitted in exchanged SDPs and not filtered out.

	var filteredSDP []byte
	filteredSDP, logFields, err = offerRequest.ValidateAndGetLogFields(
		int(atomic.LoadInt64(&b.maxCompartmentIDs)),
		b.config.LookupGeoIP,
		b.config.APIParameterValidator,
		b.config.APIParameterLogFieldFormatter,
		geoIPData)
	if err != nil {
		return nil, errors.Trace(err)
	}

	hasPersonalCompartmentIDs := len(offerRequest.PersonalCompartmentIDs) > 0

	offerSDP := offerRequest.ClientOfferSDP
	offerSDP.SDP = string(filteredSDP)

	// AllowClient may be used to disallow clients from certain geolocations
	// from offering. Clients are always allowed to match proxies with shared
	// personal compartment IDs.

	if !hasPersonalCompartmentIDs &&
		!b.config.AllowClient(geoIPData) {

		return nil, errors.TraceNew("client disallowed")
	}

	// Validate that the proxy destination specified by the client is a valid
	// dial address for a signed Psiphon server entry. This ensures a client
	// can't misuse a proxy to connect to arbitrary destinations.

	serverParams, err = b.validateDestination(
		geoIPData,
		offerRequest.PackedDestinationServerEntry,
		offerRequest.NetworkProtocol,
		offerRequest.DestinationAddress)
	if err != nil {

		// Record the specific error in the client-offer broker event.
		limitedErr = err

		// Return a response. This avoids returning a broker-client-resetting
		// 404 in cases including "invalid server entry tag", where a
		// legitimate client submits an unpruned, decommissioned server entry.
		responsePayload, err := MarshalClientOfferResponse(
			&ClientOfferResponse{Limited: true})
		if err != nil {
			return nil, errors.Trace(err)
		}

		return responsePayload, nil
	}

	// Return MustUpgrade when the client's protocol version is less than the
	// minimum required.
	if offerRequest.Metrics.ProtocolVersion < minimumClientProtocolVersion {
		responsePayload, err := MarshalClientOfferResponse(
			&ClientOfferResponse{
				NoMatch:     true,
				MustUpgrade: true,
			})
		if err != nil {
			return nil, errors.Trace(err)
		}

		return responsePayload, nil
	}

	// Enqueue the client offer and await a proxy matching and subsequent
	// proxy answer.

	// The Client Offer timeout may be configured with a shorter value in
	// personal pairing mode, to facilitate a faster no-match result and
	// resulting broker rotation.
	var timeout time.Duration
	if hasPersonalCompartmentIDs {
		timeout = time.Duration(atomic.LoadInt64(&b.clientOfferPersonalTimeout))
	} else {
		timeout = time.Duration(atomic.LoadInt64(&b.clientOfferTimeout))
	}
	timeout = common.ValueOrDefault(timeout, brokerClientOfferTimeout)

	// Adjust the timeout to respect any shorter maximum request timeouts for
	// the fronting provider.
	timeout = b.adjustRequestTimeout(logFields, timeout)

	offerCtx, cancelFunc := context.WithTimeout(ctx, timeout)
	defer cancelFunc()
	extendTransportTimeout(timeout)

	clientMatchOffer = &MatchOffer{
		Properties: MatchProperties{
			ProtocolVersion:        offerRequest.Metrics.ProtocolVersion,
			CommonCompartmentIDs:   offerRequest.CommonCompartmentIDs,
			PersonalCompartmentIDs: offerRequest.PersonalCompartmentIDs,
			GeoIPData:              geoIPData,
			NetworkType:            GetNetworkType(offerRequest.Metrics.BaseAPIParameters),
			NATType:                offerRequest.Metrics.NATType,
			PortMappingTypes:       offerRequest.Metrics.PortMappingTypes,
		},
		ClientOfferSDP:              offerSDP,
		ClientRootObfuscationSecret: offerRequest.ClientRootObfuscationSecret,
		DoDTLSRandomization:         offerRequest.DoDTLSRandomization,
		UseMediaStreams:             offerRequest.UseMediaStreams,
		TrafficShapingParameters:    offerRequest.TrafficShapingParameters,
		NetworkProtocol:             offerRequest.NetworkProtocol,
		DestinationAddress:          offerRequest.DestinationAddress,
		DestinationServerID:         serverParams.serverID,
	}

	proxyAnswer, proxyMatchAnnouncement, matchMetrics, err = b.matcher.Offer(
		offerCtx,
		clientIP,
		clientMatchOffer)
	if err != nil {

		var limitError *MatcherLimitError
		limited := std_errors.As(err, &limitError)

		timeout := offerCtx.Err() == context.DeadlineExceeded

		// A no-match response is sent in the case of a timeout awaiting a
		// match. The faster-failing rate or entry limiting case also results
		// in a response, rather than an error return from handleClientOffer,
		// so that the client doesn't receive a 404 and flag its BrokerClient
		// as having failed.
		//
		// When the timeout and limit cases coincide, limit takes precedence in
		// the response.

		if timeout {

			// Record the time out outcome in the client-offer broker event.
			//
			// Note: the respective client and broker timeouts,
			// InproxyBrokerClientOfferTimeout and
			// InproxyClientOfferRequestTimeout in tactics, should be configured
			// so that the broker will timeout first and have an opportunity to
			// send this response before the client times out.
			timedOut = true
		}

		if limited {

			// Record the specific limit error in the client-offer broker event.
			limitedErr = err
		}

		if !limited && !timeout {

			// If matcher.Offer failed for some other reason, default to
			// returning Limited in the response. As currently implemented,
			// when clients receive the Limited flag, they will fail the
			// in-proxy dial without retrying, but retain their broker client.
			//
			// While the matcher.Offer failure scenarios may include an
			// internal error, they also include the "no answer" case where a
			// proxy fails to produce an answer. For the "no answer" case,
			// Limited is preferred over returning NoMatch, which can trigger
			// a broker client cycle.
			//
			// TODO: add a new flag to signal to the client that it may retry
			// in the "no answer" case.
			limited = true
			limitedErr = err
		}

		responsePayload, err := MarshalClientOfferResponse(
			&ClientOfferResponse{
				Limited: limited,
				NoMatch: timeout && !limited,
			})
		if err != nil {
			return nil, errors.Trace(err)
		}

		return responsePayload, nil
	}

	// Log the type of compartment matching that occurred. As
	// PersonalCompartmentIDs are user-generated and shared, actual matching
	// values are not logged as they may link users.

	// TODO: log matching common compartment IDs?

	matchedCommonCompartments := HaveCommonIDs(
		proxyMatchAnnouncement.Properties.CommonCompartmentIDs,
		clientMatchOffer.Properties.CommonCompartmentIDs)

	matchedPersonalCompartments := HaveCommonIDs(
		proxyMatchAnnouncement.Properties.PersonalCompartmentIDs,
		clientMatchOffer.Properties.PersonalCompartmentIDs)

	// Initiate a BrokerServerReport, which sends important information
	// about the connection, including the original client IP, plus other
	// values to be logged with server_tunne, to the server. The report is
	// sent through a secure session established between the broker and the
	// server, relayed by the client.
	//
	// The first relay message will be embedded in the Psiphon handshake. The
	// broker may already have an established session with the server. In
	// this case, only only that initial message is required. The
	// BrokerServerReport is a one-way message, which avoids extra untunneled
	// client/broker traffic.
	//
	// Limitations, due to the one-way message:
	// - the broker can't actively clean up pendingServerReports as
	//   tunnels are established and must rely on cache expiry.
	// - the broker doesn't learn that the server accepted the report, and
	//   so cannot log a final connection status or signal the proxy to
	//   disconnect the client in any misuse cases.
	//
	// As a future enhancement, consider adding a _tunneled_ client relay
	// of a server response acknowledging the broker report.

	relayPacket, err := b.initiateRelayedServerReport(
		serverParams,
		proxyAnswer.ConnectionID,
		&BrokerServerReport{
			ProxyID:                     proxyAnswer.ProxyID,
			ConnectionID:                proxyAnswer.ConnectionID,
			MatchedCommonCompartments:   matchedCommonCompartments,
			MatchedPersonalCompartments: matchedPersonalCompartments,
			ClientNATType:               clientMatchOffer.Properties.NATType,
			ClientPortMappingTypes:      clientMatchOffer.Properties.PortMappingTypes,
			ClientIP:                    clientIP,
			ProxyIP:                     proxyAnswer.ProxyIP,
			// ProxyMetrics includes proxy NAT and port mapping types.
			ProxyMetrics:    proxyMatchAnnouncement.ProxyMetrics,
			ProxyIsPriority: proxyMatchAnnouncement.Properties.IsPriority,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Select the protocol version. The matcher has already checked
	// negotiateProtocolVersion, so failure is not expected.

	negotiatedProtocolVersion, ok := negotiateProtocolVersion(
		proxyMatchAnnouncement.Properties.ProtocolVersion,
		offerRequest.Metrics.ProtocolVersion,
		offerRequest.UseMediaStreams)
	if !ok {
		return nil, errors.TraceNew("unexpected negotiateProtocolVersion failure")
	}

	// Respond with the proxy answer and initial broker/server session packet.

	responsePayload, err := MarshalClientOfferResponse(
		&ClientOfferResponse{
			ConnectionID:            proxyAnswer.ConnectionID,
			SelectedProtocolVersion: negotiatedProtocolVersion,
			ProxyAnswerSDP:          proxyAnswer.ProxyAnswerSDP,
			RelayPacketToServer:     relayPacket,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

// handleProxyAnswer receives a proxy answer and delivers it to the waiting
// client.
func (b *Broker) handleProxyAnswer(
	ctx context.Context,
	extendTransportTimeout ExtendTransportTimeout,
	transportLogFields common.LogFields,
	proxyIP string,
	geoIPData common.GeoIPData,
	initiatorID ID,
	requestPayload []byte) (retResponse []byte, retErr error) {

	startTime := time.Now()

	var logFields common.LogFields
	var proxyAnswer *MatchAnswer
	var answerError string

	// The proxy ID is an implicit parameter: it's the proxy's session public
	// key.
	proxyID := initiatorID

	// Always log the outcome.
	defer func() {
		if logFields == nil {
			logFields = b.config.APIParameterLogFieldFormatter("", geoIPData, nil)
		}
		logFields["broker_event"] = "proxy-answer"
		logFields["broker_id"] = b.brokerID
		logFields["proxy_id"] = proxyID
		logFields["elapsed_time"] = time.Since(startTime) / time.Millisecond
		if proxyAnswer != nil {
			logFields["connection_id"] = proxyAnswer.ConnectionID
		}
		if answerError != "" {
			// This is a proxy-reported error that occurred while creating the answer.
			logFields["answer_error"] = answerError
		}
		if retErr != nil {
			logFields["error"] = retErr.Error()
		}
		logFields.Add(transportLogFields)
		b.config.Logger.LogMetric(brokerMetricName, logFields)
	}()

	answerRequest, err := UnmarshalProxyAnswerRequest(requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The filtered SDP is the request SDP with any invalid (bogon, unexpected
	// GeoIP) ICE candidates filtered out. In some cases, proxies cannot
	// avoid submitting invalid candidates (see comment in
	// processSDPAddresses), so all invalid candidates are removed and the
	// remaining SDP is used. Filtered candidate information is logged in
	// logFields.
	//
	// In personal pairing mode, RFC 1918/4193 private IP addresses are
	// permitted in exchanged SDPs and not filtered out.

	hasPersonalCompartmentIDs, err := b.matcher.AnnouncementHasPersonalCompartmentIDs(
		initiatorID, answerRequest.ConnectionID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var filteredSDP []byte
	filteredSDP, logFields, err = answerRequest.ValidateAndGetLogFields(
		b.config.LookupGeoIP,
		b.config.APIParameterValidator,
		b.config.APIParameterLogFieldFormatter,
		geoIPData,
		hasPersonalCompartmentIDs)
	if err != nil {
		return nil, errors.Trace(err)
	}

	answerSDP := answerRequest.ProxyAnswerSDP
	answerSDP.SDP = string(filteredSDP)

	if answerRequest.AnswerError != "" {

		// The proxy failed to create an answer.

		answerError = answerRequest.AnswerError

		b.matcher.AnswerError(initiatorID, answerRequest.ConnectionID)

	} else {

		// Deliver the answer to the client.

		// Note that neither ProxyID nor ProxyIP is returned to the client.
		// These fields are used internally in the matcher.

		proxyAnswer = &MatchAnswer{
			ProxyIP:        proxyIP,
			ProxyID:        initiatorID,
			ConnectionID:   answerRequest.ConnectionID,
			ProxyAnswerSDP: answerSDP,
		}

		err = b.matcher.Answer(proxyAnswer)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// There is no data in this response, it's simply an acknowledgement that
	// the answer was received. Upon receiving the response, the proxy should
	// begin the WebRTC dial operation.

	responsePayload, err := MarshalProxyAnswerResponse(
		&ProxyAnswerResponse{})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

// handleServerProxyQuality receives, from servers, proxy tunnel quality and
// records that in the proxy quality state that is used to prioritize
// well-performing proxies.
func (b *Broker) handleServerProxyQuality(
	ctx context.Context,
	extendTransportTimeout ExtendTransportTimeout,
	transportLogFields common.LogFields,
	proxyIP string,
	geoIPData common.GeoIPData,
	initiatorID ID,
	requestPayload []byte) (retResponse []byte, retErr error) {

	startTime := time.Now()

	var logFields common.LogFields

	// Only known, trusted Psiphon server initiators are allowed to send proxy
	// quality requests. knownServerInitiatorIDs is populated with the
	// Curve25519 public keys -- initiator IDs -- corresponding to the
	// session public keys found in signed Psiphon server entries.
	//
	// Currently, knownServerInitiatorIDs is populated with destination server
	// entries received in client offers, so the broker must first receive a
	// client offer before a given server is trusted, which means
	// that "invalid initiator" errors may occur, and some quality requests
	// may be dropped, in some expected situations, including a broker restart.

	// serverID is the server entry diagnostic ID of the server.
	serverIDValue, ok := b.knownServerInitiatorIDs.Load(initiatorID)
	if !ok {
		return nil, errors.TraceNew("invalid initiator")
	}
	serverID := serverIDValue.(string)

	// Always log the outcome.
	defer func() {

		// Typically, a server will send the same proxy quality request to all
		// brokers. For the one "broadcast" request, server-proxy-quality is
		// logged by each broker, as an indication that every server/broker
		// request pair is successful.
		//
		// TODO: log more details from ServerProxyQualityRequest.QualityCounts?

		if logFields == nil {
			logFields = common.LogFields{}
		}
		logFields["broker_event"] = "server-proxy-quality"
		logFields["broker_id"] = b.brokerID
		logFields["elapsed_time"] = time.Since(startTime) / time.Millisecond
		logFields["server_id"] = serverID
		if retErr != nil {
			logFields["error"] = retErr.Error()
		}
		logFields.Add(transportLogFields)
		b.config.Logger.LogMetric(brokerMetricName, logFields)
	}()

	qualityRequest, err := UnmarshalServerProxyQualityRequest(requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	logFields, err = qualityRequest.ValidateAndGetLogFields()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Add the quality counts into the existing proxy quality state.
	//
	// The counts are ignored when proxy quality is disabled, but an
	// anknowledgement is still returned to the server.

	if b.enableProxyQuality.Load() {
		for proxyKey, counts := range qualityRequest.QualityCounts {
			b.proxyQualityState.AddQuality(proxyKey, counts)
		}
	}

	// There is no data in this response, it's simply an acknowledgement that
	// the request was received.

	responsePayload, err := MarshalServerProxyQualityResponse(
		&ServerProxyQualityResponse{})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

// handleClientRelayedPacket facilitates broker/server sessions. The initial
// packet from the broker is sent to the client in the ClientOfferResponse.
// The client sends that to the server in the Psiphon handshake. If the
// session was already established, the relay ends there. Otherwise, the
// client receives any packet sent back by the server and that server packet
// is then delivered to the broker in a ClientRelayedPacketRequest. If the
// session needs to be [re-]negotiated, there are additional
// ClientRelayedPacket round trips until the session is established and the
// BrokerServerReport is securely exchanged between the broker and server.
func (b *Broker) handleClientRelayedPacket(
	ctx context.Context,
	extendTransportTimeout ExtendTransportTimeout,
	transportLogFields common.LogFields,
	geoIPData common.GeoIPData,
	initiatorID ID,
	requestPayload []byte) (retResponse []byte, retErr error) {

	startTime := time.Now()

	var logFields common.LogFields
	var relayedPacketRequest *ClientRelayedPacketRequest
	var serverID string

	// Always log the outcome.
	defer func() {
		if logFields == nil {
			logFields = b.config.APIParameterLogFieldFormatter("", geoIPData, nil)
		}
		logFields["broker_event"] = "client-relayed-packet"
		logFields["broker_id"] = b.brokerID
		logFields["elapsed_time"] = time.Since(startTime) / time.Millisecond
		if relayedPacketRequest != nil {
			logFields["connection_id"] = relayedPacketRequest.ConnectionID
		}
		if serverID != "" {
			logFields["destination_server_id"] = serverID
		}
		if retErr != nil {
			logFields["error"] = retErr.Error()
		}
		logFields.Add(transportLogFields)
		b.config.Logger.LogMetric(brokerMetricName, logFields)
	}()

	relayedPacketRequest, err := UnmarshalClientRelayedPacketRequest(requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	logFields, err = relayedPacketRequest.ValidateAndGetLogFields(
		b.config.APIParameterValidator,
		b.config.APIParameterLogFieldFormatter,
		geoIPData)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The relay state is associated with the connection ID.

	strConnectionID := string(relayedPacketRequest.ConnectionID[:])

	entry, ok := b.pendingServerReports.Get(strConnectionID)
	if !ok {
		// The relay state is not found; it may have been evicted from the
		// cache. The client will receive a generic error in this case and
		// should stop relaying. Assuming the server is configured to require
		// a BrokerServerReport, the tunnel will be terminated, so the
		// client should also abandon the dial.
		return nil, errors.TraceNew("no pending report")
	}
	pendingServerReport := entry.(*pendingServerReport)

	serverID = pendingServerReport.serverID

	// When the broker tried to use an existing session that was expired on the
	// server, the server will respond here with a signed session reset token. The
	// broker resets the session and starts to establish a new session.
	//
	// The non-waiting session establishment mode is used for broker/server
	// sessions: if multiple clients concurrently try to relay new sessions,
	// all establishments will happen in parallel without forcing any clients
	// to wait for one client to lead the establishment. The last established
	// session will be retained for reuse.
	//
	// If there is an error, the relayed packet is invalid. Drop the packet
	// and return an error to be logged. Do _not_ reset the session,
	// otherwise a malicious client could interrupt a valid broker/server
	// session with a malformed packet.

	// Next is given a nil ctx since we're not waiting for any other client to
	// establish the session.
	out, _, err := pendingServerReport.roundTrip.Next(
		nil, relayedPacketRequest.PacketFromServer)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if out == nil {

		// The BrokerServerReport is a one-way message, As a result, the relay
		// never ends with broker receiving a response; it's either
		// (re)handshaking or sending the one-way report.

		return nil, errors.TraceNew("unexpected nil packet")
	}

	// Return the next broker packet for the client to relay to the server.
	// When it receives a nil PacketToServer, the client will stop relaying.

	responsePayload, err := MarshalClientRelayedPacketResponse(
		&ClientRelayedPacketResponse{
			PacketToServer: out,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

func (b *Broker) adjustRequestTimeout(
	logFields common.LogFields, timeout time.Duration) time.Duration {

	// Adjust long-polling request timeouts to respect any maximum request
	// timeout supported by the provider fronting the request.
	//
	// Limitation: the client is trusted to provide the correct fronting
	// provider ID.

	maxRequestTimeouts, ok := b.maxRequestTimeouts.Load().(map[string]time.Duration)
	if !ok || maxRequestTimeouts == nil {
		return timeout
	}

	frontingProviderID, ok := logFields["fronting_provider_id"].(string)
	if !ok {
		return timeout
	}

	maxRequestTimeout, ok := maxRequestTimeouts[frontingProviderID]
	if !ok || maxRequestTimeout <= 0 || timeout <= maxRequestTimeout {
		return timeout
	}

	return maxRequestTimeout
}

type pendingServerReport struct {
	serverID     string
	serverReport *BrokerServerReport
	roundTrip    *InitiatorRoundTrip
}

func (b *Broker) initiateRelayedServerReport(
	serverParams *serverParams,
	connectionID ID,
	serverReport *BrokerServerReport) ([]byte, error) {

	reportPayload, err := MarshalBrokerServerReport(serverReport)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Force a new, concurrent session establishment with the server even if
	// another handshake is already in progess, relayed by some other client.
	// This ensures clients don't block waiting for other client relays
	// through other tunnels. The last established session will be retained
	// for reuse.

	waitToShareSession := false

	roundTrip, err := b.initiatorSessions.NewRoundTrip(
		serverParams.sessionPublicKey,
		serverParams.sessionRootObfuscationSecret,
		waitToShareSession,
		reportPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	relayPacket, _, err := roundTrip.Next(nil, nil)
	if err != nil {
		return nil, errors.Trace(err)
	}

	strConnectionID := string(connectionID[:])

	b.pendingServerReports.Set(
		strConnectionID,
		&pendingServerReport{
			serverID:     serverParams.serverID,
			serverReport: serverReport,
			roundTrip:    roundTrip,
		},
		time.Duration(atomic.LoadInt64(&b.pendingServerReportsTTL)))

	return relayPacket, nil
}

type serverParams struct {
	serverID                     string
	sessionPublicKey             SessionPublicKey
	sessionRootObfuscationSecret ObfuscationSecret
}

// validateDestination checks that the client's specified proxy dial
// destination is valid destination address for a tunnel protocol in the
// specified signed and valid Psiphon server entry.
func (b *Broker) validateDestination(
	geoIPData common.GeoIPData,
	packedDestinationServerEntry []byte,
	networkProtocol NetworkProtocol,
	destinationAddress string) (*serverParams, error) {

	var packedServerEntry protocol.PackedServerEntryFields
	err := cbor.Unmarshal(packedDestinationServerEntry, &packedServerEntry)
	if err != nil {
		return nil, errors.Trace(err)
	}

	serverEntryFields, err := protocol.DecodePackedServerEntryFields(packedServerEntry)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Strip any unsigned fields, which could be forged by the client. In
	// particular, this includes the server entry tag, which, in some cases,
	// is locally populated by a client for its own reference.

	serverEntryFields.RemoveUnsignedFields()

	// Check that the server entry is signed by Psiphon. Otherwise a client
	// could manufacture a server entry corresponding to an arbitrary dial
	// destination.

	err = serverEntryFields.VerifySignature(
		b.config.ServerEntrySignaturePublicKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The server entry tag must be set and signed by Psiphon, as local,
	// client derived tags are unsigned and untrusted.

	serverEntryTag := serverEntryFields.GetTag()

	if serverEntryTag == "" {
		return nil, errors.TraceNew("missing server entry tag")
	}

	// Check that the server entry tag is on a list of active and valid
	// Psiphon server entry tags. This ensures that an obsolete entry for a
	// pruned server cannot by misused by a client to proxy to what's no
	// longer a Psiphon server.

	if !b.config.IsValidServerEntryTag(serverEntryTag) {
		return nil, errors.TraceNew("invalid server entry tag")
	}

	serverID := serverEntryFields.GetDiagnosticID()

	serverEntry, err := serverEntryFields.GetServerEntry()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Validate the dial host (IP or domain) and port matches a tunnel
	// protocol offered by the server entry.

	destHost, destPort, err := net.SplitHostPort(destinationAddress)
	if err != nil {
		return nil, errors.Trace(err)
	}

	destPortNum, err := strconv.Atoi(destPort)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// For domain fronted cases, since we can't verify the Host header, access
	// is strictly to limited to targeted clients. Clients should use tactics
	// to avoid disallowed domain dial address cases, but here the broker
	// enforces it.
	//
	// TODO: this issue could be further mitigated with a server
	// acknowledgement of the broker's report, with no acknowledgement
	// followed by signaling the proxy to terminate client connection.

	// This assumes that any domain dial is for domain fronting.
	isDomain := net.ParseIP(destHost) == nil
	if isDomain && !b.config.AllowDomainFrontedDestinations(geoIPData) {
		return nil, errors.TraceNew("domain fronted destinations disallowed")
	}

	// The server entry must include an in-proxy tunnel protocol capability
	// and corresponding dial port number. In-proxy capacity may be set for
	// only a subset of all Psiphon servers, to limited the number of servers
	// a proxy can observe and enumerate. Well-behaved clients will not send
	// any server entries lacking this capability, but here the broker
	// enforces it.

	if !serverEntry.IsValidInproxyDialAddress(networkProtocol.String(), destHost, destPortNum) {
		return nil, errors.TraceNew("invalid destination address")
	}

	// Extract and return the key material to be used for the secure session
	// and BrokerServer exchange between the broker and the Psiphon server
	// corresponding to this server entry.

	params := &serverParams{
		serverID: serverID,
	}

	params.sessionPublicKey, err = SessionPublicKeyFromString(
		serverEntry.InproxySessionPublicKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	params.sessionRootObfuscationSecret, err = ObfuscationSecretFromString(
		serverEntry.InproxySessionRootObfuscationSecret)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Record that this server is known and trusted ServerProxyQualityRequest
	// sender. The serverID is stored for logging in handleServerProxyQuality.
	//
	// There is no expiry for knownServerInitiatorIDs entries, and they will
	// clear only if the broker is restarted (which is the same lifetime as
	// ServerEntrySignaturePublicKey).
	//
	// Limitation: in time, the above IsValidServerEntryTag check could become
	// false for a retired server, while its entry remains in
	// knownServerInitiatorIDs. However, unlike the case of a recycled
	// Psiphon server IP being used as a proxy destination, it's safer to
	// assume that a retired server's session private key does not become
	// exposed.

	serverInitiatorID, err := params.sessionPublicKey.ToCurve25519()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// For hosts running a single psiphond with multiple server entries, there
	// will be multiple possible serverIDs for one serverInitiatorID. Don't
	// overwrite any existing entry; keep the first observed serverID for
	// more stable logging.

	_, _ = b.knownServerInitiatorIDs.LoadOrStore(ID(serverInitiatorID), serverID)

	return params, nil
}

func (b *Broker) isCommonCompartmentIDHashingInitialized() bool {
	b.commonCompartmentsMutex.Lock()
	defer b.commonCompartmentsMutex.Unlock()
	return b.commonCompartments != nil
}

func (b *Broker) initializeCommonCompartmentIDHashing(
	commonCompartmentIDs []ID) error {

	b.commonCompartmentsMutex.Lock()
	defer b.commonCompartmentsMutex.Unlock()

	// At least one common compartment ID is required. At a minimum, one ID
	// will be used and distributed to clients via tactics, limiting matching
	// to those clients targeted to receive that tactic parameters.
	if len(commonCompartmentIDs) == 0 {
		return errors.TraceNew("missing common compartment IDs")
	}

	// The consistent package doesn't allow duplicate members.
	checkDup := make(map[ID]bool, len(commonCompartmentIDs))
	for _, compartmentID := range commonCompartmentIDs {
		if checkDup[compartmentID] {
			return errors.TraceNew("duplicate common compartment IDs")
		}
		checkDup[compartmentID] = true
	}

	// Proxies without personal compartment IDs are randomly assigned to the
	// set of common, Psiphon-specified, compartment IDs. These common
	// compartment IDs are then distributed to targeted clients through
	// tactics or embedded in OSLs, to limit access to proxies.
	//
	// Use consistent hashing in an effort to keep a consistent assignment of
	// proxies (as specified by proxy ID, which covers all announcements for
	// a single proxy). This is more of a concern for long-lived, permanent
	// proxies that are not behind any NAT.
	//
	// Even with consistent hashing, a subset of proxies will still change
	// assignment when CommonCompartmentIDs changes.

	consistentMembers := make([]consistent.Member, len(commonCompartmentIDs))
	for i, compartmentID := range commonCompartmentIDs {
		consistentMembers[i] = consistentMember(compartmentID.String())
	}

	b.commonCompartments = consistent.New(
		consistentMembers,
		consistent.Config{
			PartitionCount:    len(consistentMembers),
			ReplicationFactor: 1,
			Load:              1,
			Hasher:            xxhasher{},
		})

	return nil
}

// xxhasher wraps github.com/cespare/xxhash.Sum64 in the interface expected by
// github.com/buraksezer/consistent. xxhash is a high quality hash function
// used in github.com/buraksezer/consistent examples.
type xxhasher struct{}

func (h xxhasher) Sum64(data []byte) uint64 {
	return xxhash.Sum64(data)
}

// consistentMember wraps the string type with the interface expected by
// github.com/buraksezer/consistent.
type consistentMember string

func (m consistentMember) String() string {
	return string(m)
}

func (b *Broker) selectCommonCompartmentID(proxyID ID) (ID, error) {

	b.commonCompartmentsMutex.Lock()
	defer b.commonCompartmentsMutex.Unlock()

	compartmentID, err := IDFromString(
		b.commonCompartments.LocateKey(proxyID[:]).String())
	if err != nil {
		return compartmentID, errors.Trace(err)
	}

	return compartmentID, nil
}
