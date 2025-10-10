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

/*
Package tactics provides dynamic Psiphon client configuration based on GeoIP
attributes, API parameters, and speed test data. The tactics implementation
works in concert with the "parameters" package, allowing contextual
optimization of Psiphon client parameters; for example, customizing
NetworkLatencyMultiplier to adjust timeouts for clients on slow networks; or
customizing LimitTunnelProtocols and ConnectionWorkerPoolSize to circumvent
specific blocking conditions.

Clients obtain tactics from a Psiphon server. Tactics are configured with a hot-
reloadable, JSON format server config file. The config file specifies default
tactics for all clients as well as a list of filtered tactics. For each filter,
if the client's attributes satisfy the filter then additional tactics are merged
into the tactics set provided to the client.

Tactics configuration is optimized for a modest number of filters -- dozens --
and very many GeoIP matches in each filter.

A Psiphon client "tactics request" is an an untunneled, pre-establishment
request to obtain tactics, which will in turn be applied and used in the normal
tunnel establishment sequence; the tactics request may result in custom
timeouts, protocol selection, and other tunnel establishment behavior.

The client will delay its normal establishment sequence and launch a tactics
request only when it has no stored, valid tactics for its current network
context. The normal establishment sequence will begin, regardless of tactics
request outcome, after TacticsWaitPeriod; this ensures that the client will not
stall its establishment process when the tactics request cannot complete.

Tactics are configured with a TTL, which is converted to an expiry time on the
client when tactics are received and stored. When the client starts its
establishment sequence and finds stored, unexpired tactics, no tactics request
is made. The expiry time serves to prevent execess tactics requests and avoid a
fingerprintable network sequence that would result from always performing the
tactics request.

The client calls UseStoredTactics to check for stored tactics; and if none is
found (there is no record or it is expired) the client proceeds to call
FetchTactics to make the tactics request.

In the Psiphon client and server, the tactics request is transported using the
meek protocol. In this case, meek is configured as a simple HTTP round trip
transport and does not relay arbitrary streams of data and does not allocate
resources required for relay mode. On the Psiphon server, the same meek
component handles both tactics requests and tunnel relays. Anti-probing for
tactics endpoints are thus provided as usual by meek. A meek request is routed
based on an routing field in the obfuscated meek cookie.

As meek may be plaintext and as TLS certificate verification is sometimes
skipped, the tactics request payload is wrapped with NaCl box and further
wrapped in a padded obfuscator. Distinct request and response nonces are used to
mitigate replay attacks. Clients generate ephemeral NaCl key pairs and the
server public key is obtained from the server entry. The server entry also
contains capabilities indicating that a Psiphon server supports tactics requests
and which meek protocol is to be used.

The Psiphon client requests, stores, and applies distinct tactics based on its
current network context. The client uses platform-specific APIs to obtain a fine
grain network ID based on, for example BSSID for WiFi or MCC/MNC for mobile.
These values provides accurate detection of network context changes and can be
obtained from the client device without any network activity. As the network ID
is personally identifying, this ID is only used by the client and is never sent
to the Psiphon server. The client obtains the current network ID from a callback
made from tunnel-core to native client code.

Tactics returned to the Psiphon client are accompanied by a "tag" which is a
hash digest of the merged tactics data. This tag uniquely identifies the
tactics. The client reports the tactics it is employing through the
"applied_tactics" common metrics API parameter. When fetching new tactics, the
client reports the stored (and possibly expired) tactics it has through the
"stored_tactics" API parameter. The stored tactics tag is used to avoid
redownloading redundant tactics data; when the tactics response indicates the
tag is unchanged, no tactics data is returned and the client simply extends the
expiry of the data is already has.

The Psiphon handshake API returns tactics in its response. This enabled regular
tactics expiry extension without requiring any distinct tactics request or
tactics data transfer when the tag is unchanged. Psiphon clients that connect
regularly and successfully with make almost no untunnled tactics requests except
for new network IDs. Returning tactics in the handshake reponse also provides
tactics in the case where a client is unable to complete an untunneled tactics
request but can otherwise establish a tunnel. Clients will abort any outstanding
untunneled tactics requests or scheduled retries once a handshake has completed.

The client handshake request component calls SetTacticsAPIParameters to populate
the handshake request parameters with tactics inputs, and calls
HandleTacticsPayload to process the tactics payload in the handshake response.

The core tactics data is custom values for a subset of the parameters in
parameters.Parameters. A client takes the default Parameters, applies any
custom values set in its config file, and then applies any stored or received
tactics. Each time the tactics changes, this process is repeated so that
obsolete tactics parameters are not retained in the client's Parameters
instance.

Speed test data is used in filtered tactics for selection of parameters such as
timeouts.

A speed test sample records the RTT of an application-level round trip to a
Psiphon server -- either a meek HTTP round trip or an SSH request round trip.
The round trip should be preformed after an TCP, TLS, SSH, etc. handshake so
that the RTT includes only the application-level round trip. Each sample also
records the tunnel/meek protocol used, the Psiphon server region, and a
timestamp; these values may be used to filter out outliers or stale samples. The
samples record bytes up/down, although at this time the speed test is focused on
latency and the payload is simply anti-fingerprint padding and should not be
larger than an IP packet.

The Psiphon client records the latest SpeedTestMaxSampleCount speed test samples
for each network context. SpeedTestMaxSampleCount should be  a modest size, as
each speed test sample is ~100 bytes when serialzied and all samples (for one
network ID) are loaded into memory and  sent as API inputs to tactics and
handshake requests.

When a tactics request is initiated and there are no speed test samples for
current network ID, the tactics request is proceeded by a speed test round trip,
using the same meek round tripper, and that sample is stored and used for the
tactics request. with a speed test The client records additional samples taken
from regular SSH keep alive round trips and calls AddSpeedTestSample to store
these.

The client sends all its speed test samples, for the current network context, to
the server in tactics and handshake requests; this allows the server logic to
handle outliers and aggregation. Currently, filtered tactics support filerting
on speed test RTT maximum, minimum, and median.
*/
package tactics

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	lrucache "github.com/cognusion/go-cache-lru"
	"golang.org/x/crypto/nacl/box"
)

// TACTICS_PADDING_MAX_SIZE is used by the client as well as the server. This
// value is not a dynamic client parameter since a tactics request is made
// only when the client has no valid tactics, so no override of
// TACTICS_PADDING_MAX_SIZE can be applied.

const (
	SPEED_TEST_END_POINT               = "speedtest"
	TACTICS_END_POINT                  = "tactics"
	MAX_REQUEST_BODY_SIZE              = 65536
	SPEED_TEST_PADDING_MIN_SIZE        = 0
	SPEED_TEST_PADDING_MAX_SIZE        = 256
	TACTICS_PADDING_MAX_SIZE           = 256
	TACTICS_OBFUSCATED_KEY_SIZE        = 32
	SPEED_TEST_SAMPLES_PARAMETER_NAME  = "speed_test_samples"
	APPLIED_TACTICS_TAG_PARAMETER_NAME = "applied_tactics_tag"
	STORED_TACTICS_TAG_PARAMETER_NAME  = "stored_tactics_tag"
	TACTICS_METRIC_EVENT_NAME          = "tactics"
	NEW_TACTICS_TAG_LOG_FIELD_NAME     = "new_tactics_tag"
	IS_TACTICS_REQUEST_LOG_FIELD_NAME  = "is_tactics_request"
	AGGREGATION_MINIMUM                = "Minimum"
	AGGREGATION_MAXIMUM                = "Maximum"
	AGGREGATION_MEDIAN                 = "Median"
	PAYLOAD_CACHE_SIZE                 = 1024
)

var (
	TACTICS_REQUEST_NONCE  = []byte{1}
	TACTICS_RESPONSE_NONCE = []byte{2}
)

// Server is a tactics server to be integrated with the Psiphon server meek and handshake
// components.
//
// The meek server calls HandleEndPoint to handle untunneled tactics and speed test requests.
// The handshake handler calls GetTacticsPayload to obtain a tactics payload to include with
// the handsake response.
//
// The Server is a reloadable file; its exported fields are read from the tactics configuration
// file.
//
// Each client will receive at least the DefaultTactics. Client GeoIP, API parameter, and speed
// test sample attributes are matched against all filters and the tactics corresponding to any
// matching filter are merged into the client tactics.
//
// The merge operation replaces any existing item in Parameter with a Parameter specified in
// the newest matching tactics. The TTL of the newest matching tactics is taken, although all
// but the DefaultTactics can omit the TTL field.
type Server struct {
	common.ReloadableFile

	// RequestPublicKey is the Server's tactics request NaCl box public key.
	RequestPublicKey []byte

	// RequestPublicKey is the Server's tactics request NaCl box private key.
	RequestPrivateKey []byte

	// RequestObfuscatedKey is the tactics request obfuscation key.
	RequestObfuscatedKey []byte

	// DefaultTactics is the baseline tactics for all clients. It must include a
	// TTL.
	DefaultTactics Tactics

	// FilteredTactics is an ordered list of filter/tactics pairs. For a client,
	// each fltered tactics is checked in order and merged into the clients
	// tactics if the client's attributes satisfy the filter.
	FilteredTactics []struct {
		Filter  Filter
		Tactics Tactics
	}

	// When no tactics configuration file is provided, there will be no
	// request key material or default tactics, and the server will not
	// support tactics. The loaded flag, set to true only when a configuration
	// file has been successfully loaded, provides an explict check for this
	// condition (vs., say, checking for a zero-value Server).
	loaded bool

	filterGeoIPScope   int
	filterRegionScopes map[string]int

	logger                common.Logger
	logFieldFormatter     common.APIParameterLogFieldFormatter
	apiParameterValidator common.APIParameterValidator

	cachedTacticsData *lrucache.Cache
	filterMatches     *sync.Pool
}

const (
	GeoIPScopeRegion = 1
	GeoIPScopeISP    = 2
	GeoIPScopeASN    = 4
	GeoIPScopeCity   = 8
)

// Filter defines a filter to match against client attributes.
// Each field within the filter is optional and may be omitted.
type Filter struct {

	// Regions specifies a list of GeoIP regions/countries the client
	// must match.
	Regions []string

	// ISPs specifies a list of GeoIP ISPs the client must match.
	ISPs []string

	// ASNs specifies a list of GeoIP ASNs the client must match.
	ASNs []string

	// Cities specifies a list of GeoIP Cities the client must match.
	Cities []string

	// APIParameters specifies API, e.g. handshake, parameter names and
	// a list of values, one of which must be specified to match this
	// filter. Only scalar string API parameters may be filtered.
	// Values may be patterns containing the '*' wildcard.
	APIParameters map[string][]string

	// Min/MaxClientVersion specify version constraints the client must match.
	MinClientVersion *int
	MaxClientVersion *int

	// SpeedTestRTTMilliseconds specifies a Range filter field that the
	// client speed test samples must satisfy.
	SpeedTestRTTMilliseconds *Range

	regionLookup map[string]bool
	ispLookup    map[string]bool
	asnLookup    map[string]bool
	cityLookup   map[string]bool
}

// Range is a filter field which specifies that the aggregation of
// the a client attribute is within specified upper and lower bounds.
// At least one bound must be specified.
//
// For example, Range is to aggregate and filter client speed test
// sample RTTs.
type Range struct {

	// Aggregation may be "Maximum", "Minimum", or "Median"
	Aggregation string

	// AtLeast specifies a lower bound for the aggregarted
	// client value.
	AtLeast *int

	// AtMost specifies an upper bound for the aggregarted
	// client value.
	AtMost *int
}

// Payload is the data to be returned to the client in response to a
// tactics request or in the handshake response.
type Payload struct {

	// Tag is the hash  tag of the accompanying Tactics. When the Tag
	// is the same as the stored tag the client specified in its
	// request, the Tactics will be empty as the client already has the
	// correct data.
	Tag string

	// Tactics is a JSON-encoded Tactics struct and may be nil.
	Tactics json.RawMessage
}

// Record is the tactics data persisted by the client. There is one
// record for each network ID.
type Record struct {

	// The Tag is the hash of the tactics data and is used as the
	// stored tag when making requests.
	Tag string

	// Expiry is the time when this perisisted tactics expires as
	// determined by the client applying the TTL against its local
	// clock when the tactics was stored.
	Expiry time.Time

	// Tactics is the core tactics data.
	Tactics Tactics
}

// Tactics is the core tactics data. This is both what is set in
// in the server configuration file and what is stored and used
// by the cient.
type Tactics struct {

	// TTL is a string duration (e.g., "24h", the syntax supported
	// by time.ParseDuration). This specifies how long the client
	// should use the accompanying tactics until it expires.
	//
	// The client stores the TTL to use for extending the tactics
	// expiry when a tactics request or handshake response returns
	// no tactics data when the tag is unchanged.
	TTL string

	// Probability is an obsolete field which is no longer used, as overall
	// tactics are now applied unconditionally; but it must be present, and
	// greater than zero, in marshaled tactics, sent by the server, for
	// compatibility with legacy client tactics validation.
	Probability float64

	// Parameters specify client parameters to override. These must
	// be a subset of parameter.ClientParameter values and follow
	// the corresponding data type and minimum value constraints.
	Parameters map[string]interface{}
}

// Note: the SpeedTestSample json tags are selected to minimize marshaled
// size. In psiphond, for logging metrics, the field names are translated to
// more verbose values. psiphon/server.makeSpeedTestSamplesLogField currently
// hard-codes these same SpeedTestSample json tag values for that translation.

// SpeedTestSample is speed test data for a single RTT event.
type SpeedTestSample struct {

	// Timestamp is the speed test event time, and may be used to discard
	// stale samples. The server supplies the speed test timestamp. This
	// value is truncated to the nearest hour as a privacy measure.
	Timestamp time.Time `json:"s"`

	// EndPointRegion is the region of the endpoint, the Psiphon server,
	// used for the speed test. This may be used to exclude outlier samples
	// using remote data centers.
	EndPointRegion string `json:"r"`

	// EndPointProtocol is the tactics or tunnel protocol use for the
	// speed test round trip. The protocol may impact RTT.
	EndPointProtocol string `json:"p"`

	// All speed test samples should measure RTT as the time to complete
	// an application-level round trip on top of a previously established
	// tactics or tunnel prococol connection. The RTT should not include
	// TCP, TLS, or SSH handshakes.
	// This value is truncated to the nearest millisecond as a privacy
	// measure.
	RTTMilliseconds int `json:"t"`

	// BytesUp is the size of the upstream payload in the round trip.
	// Currently, the payload is limited to anti-fingerprint padding.
	BytesUp int `json:"u"`

	// BytesDown is the size of the downstream payload in the round trip.
	// Currently, the payload is limited to anti-fingerprint padding.
	BytesDown int `json:"d"`
}

// GenerateKeys generates a tactics request key pair and obfuscation key.
func GenerateKeys() (encodedRequestPublicKey, encodedRequestPrivateKey, encodedObfuscatedKey string, err error) {

	requestPublicKey, requestPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", errors.Trace(err)
	}

	obfuscatedKey, err := common.MakeSecureRandomBytes(TACTICS_OBFUSCATED_KEY_SIZE)
	if err != nil {
		return "", "", "", errors.Trace(err)
	}

	return base64.StdEncoding.EncodeToString(requestPublicKey[:]),
		base64.StdEncoding.EncodeToString(requestPrivateKey[:]),
		base64.StdEncoding.EncodeToString(obfuscatedKey[:]),
		nil
}

// NewServer creates Server using the specified tactics configuration file.
//
// The logger and logFieldFormatter callbacks are used to log errors and
// metrics. The apiParameterValidator callback is used to validate client
// API parameters submitted to the tactics request.
//
// The optional requestPublicKey, requestPrivateKey, and requestObfuscatedKey
// base64 encoded string parameters may be used to specify and override the
// corresponding Server config values.
func NewServer(
	logger common.Logger,
	logFieldFormatter common.APIParameterLogFieldFormatter,
	apiParameterValidator common.APIParameterValidator,
	configFilename string,
	requestPublicKey string,
	requestPrivateKey string,
	requestObfuscatedKey string) (*Server, error) {

	server := &Server{
		logger:                logger,
		logFieldFormatter:     logFieldFormatter,
		apiParameterValidator: apiParameterValidator,
		cachedTacticsData: lrucache.NewWithLRU(
			lrucache.NoExpiration, 1*time.Minute, PAYLOAD_CACHE_SIZE),
	}

	server.ReloadableFile = common.NewReloadableFile(
		configFilename,
		true,
		func(fileContent []byte, _ time.Time) error {

			var newServer Server
			err := json.Unmarshal(fileContent, &newServer)
			if err != nil {
				return errors.Trace(err)
			}

			if requestPublicKey != "" {
				newServer.RequestPublicKey, err =
					base64.StdEncoding.DecodeString(requestPublicKey)
				if err != nil {
					return errors.Trace(err)
				}
			}

			if requestPrivateKey != "" {
				newServer.RequestPrivateKey, err =
					base64.StdEncoding.DecodeString(requestPrivateKey)
				if err != nil {
					return errors.Trace(err)
				}
			}

			if requestObfuscatedKey != "" {
				newServer.RequestObfuscatedKey, err =
					base64.StdEncoding.DecodeString(requestObfuscatedKey)
				if err != nil {
					return errors.Trace(err)
				}
			}

			err = newServer.Validate()
			if err != nil {
				return errors.Trace(err)
			}

			// Server.ReloadableFile.RWMutex is the mutex for accessing
			// these and other Server fields.

			// Modify actual traffic rules only after validation
			server.RequestPublicKey = newServer.RequestPublicKey
			server.RequestPrivateKey = newServer.RequestPrivateKey
			server.RequestObfuscatedKey = newServer.RequestObfuscatedKey
			server.DefaultTactics = newServer.DefaultTactics
			server.FilteredTactics = newServer.FilteredTactics

			// Any cached, merged tactics data is flushed when the
			// configuration changes.

			server.cachedTacticsData.Flush()

			// A pool of filterMatches, used in getTactics, is used to avoid
			// allocating a slice for every getTactics call.
			//
			// A pointer to a slice is used with sync.Pool to avoid an
			// allocation on Put, as would happen if passing in a slice
			// instead of a pointer; see
			// https://github.com/dominikh/go-tools/issues/1042#issuecomment-869064445

			server.filterMatches = &sync.Pool{
				New: func() any {
					b := make([]bool, len(server.FilteredTactics))
					return &b
				},
			}

			server.initLookups()

			server.loaded = true

			return nil
		})

	_, err := server.Reload()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return server, nil
}

// Validate checks for correct tactics configuration values.
func (server *Server) Validate() error {

	// Key material must either be entirely omitted, or fully populated.
	if len(server.RequestPublicKey) == 0 {
		if len(server.RequestPrivateKey) != 0 ||
			len(server.RequestObfuscatedKey) != 0 {
			return errors.TraceNew("unexpected request key")
		}
	} else {
		if len(server.RequestPublicKey) != 32 ||
			len(server.RequestPrivateKey) != 32 ||
			len(server.RequestObfuscatedKey) != TACTICS_OBFUSCATED_KEY_SIZE {
			return errors.TraceNew("invalid request key")
		}
	}

	// validateTactics validates either the defaultTactics, when filteredTactics
	// is nil, or the filteredTactics otherwise. In the second case,
	// defaultTactics must be passed in to validate filtered tactics references
	// to default tactics parameters, such as CustomTLSProfiles or
	// PacketManipulationSpecs.
	//
	// Limitation: references must point to the default tactics or the filtered
	// tactics itself; referring to parameters in a previous filtered tactics is
	// not suported.

	validateTactics := func(defaultTactics, filteredTactics *Tactics) error {

		tactics := defaultTactics
		validatingDefault := true
		if filteredTactics != nil {
			tactics = filteredTactics
			validatingDefault = false
		}

		// Allow "" for 0, even though ParseDuration does not.
		var d time.Duration
		if tactics.TTL != "" {
			var err error
			d, err = time.ParseDuration(tactics.TTL)
			if err != nil {
				return errors.Trace(err)
			}
		}

		if d <= 0 {
			if validatingDefault {
				return errors.TraceNew("invalid duration")
			}
			// For merging logic, Normalize any 0 duration to "".
			tactics.TTL = ""
		}

		params, err := parameters.NewParameters(nil)
		if err != nil {
			return errors.Trace(err)
		}

		applyParameters := []map[string]interface{}{
			defaultTactics.Parameters,
		}
		if filteredTactics != nil {
			applyParameters = append(
				applyParameters, filteredTactics.Parameters)
		}

		_, err = params.Set(
			"", parameters.ValidationServerSide, applyParameters...)
		if err != nil {
			return errors.Trace(err)
		}

		return nil
	}

	validateRange := func(r *Range) error {
		if r == nil {
			return nil
		}

		if (r.AtLeast == nil && r.AtMost == nil) ||
			((r.AtLeast != nil && r.AtMost != nil) && *r.AtLeast > *r.AtMost) {
			return errors.TraceNew("invalid range")
		}

		switch r.Aggregation {
		case AGGREGATION_MINIMUM, AGGREGATION_MAXIMUM, AGGREGATION_MEDIAN:
		default:
			return errors.TraceNew("invalid aggregation")
		}

		return nil
	}

	err := validateTactics(&server.DefaultTactics, nil)
	if err != nil {
		return errors.Tracef("invalid default tactics: %s", err)
	}

	for i, filteredTactics := range server.FilteredTactics {

		err := validateTactics(&server.DefaultTactics, &filteredTactics.Tactics)

		if err == nil {
			err = validateRange(filteredTactics.Filter.SpeedTestRTTMilliseconds)
		}

		// TODO: validate Filter.APIParameters names are valid?

		if err != nil {
			return errors.Tracef("invalid filtered tactics %d: %s", i, err)
		}
	}

	return nil
}

const stringLookupThreshold = 5

// initLookups creates map lookups for filters where the number
// of string values to compare against exceeds a threshold where
// benchmarks show maps are faster than looping through a string
// slice.
func (server *Server) initLookups() {

	server.filterGeoIPScope = 0
	server.filterRegionScopes = make(map[string]int)

	for _, filteredTactics := range server.FilteredTactics {

		if len(filteredTactics.Filter.Regions) >= stringLookupThreshold {
			filteredTactics.Filter.regionLookup = make(map[string]bool)
			for _, region := range filteredTactics.Filter.Regions {
				filteredTactics.Filter.regionLookup[region] = true
			}
		}

		if len(filteredTactics.Filter.ISPs) >= stringLookupThreshold {
			filteredTactics.Filter.ispLookup = make(map[string]bool)
			for _, ISP := range filteredTactics.Filter.ISPs {
				filteredTactics.Filter.ispLookup[ISP] = true
			}
		}

		if len(filteredTactics.Filter.ASNs) >= stringLookupThreshold {
			filteredTactics.Filter.asnLookup = make(map[string]bool)
			for _, ASN := range filteredTactics.Filter.ASNs {
				filteredTactics.Filter.asnLookup[ASN] = true
			}
		}

		if len(filteredTactics.Filter.Cities) >= stringLookupThreshold {
			filteredTactics.Filter.cityLookup = make(map[string]bool)
			for _, city := range filteredTactics.Filter.Cities {
				filteredTactics.Filter.cityLookup[city] = true
			}
		}

		// Initialize the filter GeoIP scope fields used by GetFilterGeoIPScope.
		//
		// The basic case is, for example, when only Regions appear in filters, then
		// only GeoIPScopeRegion is set.
		//
		// As an optimization, a regional map is populated so that, for example,
		// GeoIPScopeRegion&GeoIPScopeISP will be set only for regions for which
		// there is a filter with region and ISP, while other regions will set only
		// GeoIPScopeRegion.
		//
		// When any ISP, ASN, or City appears in a filter without a Region,
		// the regional map optimization is disabled.

		if len(filteredTactics.Filter.Regions) == 0 {
			disableRegionScope := false
			if len(filteredTactics.Filter.ISPs) > 0 {
				server.filterGeoIPScope |= GeoIPScopeISP
				disableRegionScope = true
			}
			if len(filteredTactics.Filter.ASNs) > 0 {
				server.filterGeoIPScope |= GeoIPScopeASN
				disableRegionScope = true
			}
			if len(filteredTactics.Filter.Cities) > 0 {
				server.filterGeoIPScope |= GeoIPScopeCity
				disableRegionScope = true
			}
			if disableRegionScope && server.filterRegionScopes != nil {
				for _, regionScope := range server.filterRegionScopes {
					server.filterGeoIPScope |= regionScope
				}
				server.filterRegionScopes = nil
			}
		} else {
			server.filterGeoIPScope |= GeoIPScopeRegion
			if server.filterRegionScopes != nil {
				regionScope := 0
				if len(filteredTactics.Filter.ISPs) > 0 {
					regionScope |= GeoIPScopeISP
				}
				if len(filteredTactics.Filter.ASNs) > 0 {
					regionScope |= GeoIPScopeASN
				}
				if len(filteredTactics.Filter.Cities) > 0 {
					regionScope |= GeoIPScopeCity
				}
				for _, region := range filteredTactics.Filter.Regions {
					server.filterRegionScopes[region] |= regionScope
				}
			}
		}

		// TODO: add lookups for APIParameters?
		// Not expected to be long lists of values.
	}
}

// GetFilterGeoIPScope returns which GeoIP fields are relevent to tactics
// filters. The return value is a bit array containing some combination of
// the GeoIPScopeRegion, GeoIPScopeISP, GeoIPScopeASN, and GeoIPScopeCity
// flags. For the given geoIPData, all tactics filters reference only the
// flagged fields.
func (server *Server) GetFilterGeoIPScope(geoIPData common.GeoIPData) int {

	scope := server.filterGeoIPScope

	if server.filterRegionScopes != nil {

		regionScope, ok := server.filterRegionScopes[geoIPData.Country]
		if ok {
			scope |= regionScope
		}
	}

	return scope
}

// GetTacticsPayload assembles and returns a tactics payload for a client with
// the specified GeoIP, API parameters, and speed test attributes.
//
// The speed test samples are expected to be in apiParams, as is the stored
// tactics tag.
//
// Unless no tactics configuration was loaded, GetTacticsPayload will always
// return a payload for any client. When the client's stored tactics tag is
// identical to the assembled tactics, the Payload.Tactics is nil.
//
// Elements of the returned Payload, e.g., tactics parameters, will point to
// data in DefaultTactics and FilteredTactics and must not be modifed.
//
// Callers must not mutate returned tactics data, which is cached.
func (server *Server) GetTacticsPayload(
	geoIPData common.GeoIPData,
	apiParams common.APIParameters) (*Payload, error) {

	// includeServerSideOnly is false: server-side only parameters are not
	// used by the client, so including them wastes space and unnecessarily
	// exposes the values.
	tacticsData, err := server.getTactics(false, geoIPData, apiParams)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if tacticsData == nil {
		return nil, nil
	}

	payload := &Payload{
		Tag: tacticsData.tag,
	}

	// New clients should always send STORED_TACTICS_TAG_PARAMETER_NAME. When they have no
	// stored tactics, the stored tag will be "" and not match payload.Tag and payload.Tactics
	// will be sent.
	//
	// When new clients send a stored tag that matches payload.Tag, the client already has
	// the correct data and payload.Tactics is not sent.
	//
	// Old clients will not send STORED_TACTICS_TAG_PARAMETER_NAME. In this case, do not
	// send payload.Tactics as the client will not use it, will not store it, will not send
	// back the new tag and so the handshake response will always contain wasteful tactics
	// data.

	sendPayloadTactics := true

	clientStoredTag, err := getStringRequestParam(apiParams, STORED_TACTICS_TAG_PARAMETER_NAME)

	// Old client or new client with same tag.
	if err != nil || payload.Tag == clientStoredTag {
		sendPayloadTactics = false
	}

	if sendPayloadTactics {
		payload.Tactics = tacticsData.payload
	}

	return payload, nil
}

// GetTacticsWithTag returns a GetTactics value along with the associated tag value.
//
// Callers must not mutate returned tactics data, which is cached.
func (server *Server) GetTacticsWithTag(
	includeServerSideOnly bool,
	geoIPData common.GeoIPData,
	apiParams common.APIParameters) (*Tactics, string, error) {

	tacticsData, err := server.getTactics(
		includeServerSideOnly, geoIPData, apiParams)
	if err != nil {
		return nil, "", errors.Trace(err)
	}

	if tacticsData == nil {
		return nil, "", nil
	}

	return tacticsData.tactics, tacticsData.tag, nil
}

// tacticsData is cached tactics data, including the merged Tactics object,
// the JSON marshaled paylod, and hashed tag.
type tacticsData struct {
	tactics *Tactics
	payload []byte
	tag     string
}

func newTacticsData(tactics *Tactics) (*tacticsData, error) {

	payload, err := json.Marshal(tactics)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// MD5 hash is used solely as a data checksum and not for any security
	// purpose.
	digest := md5.Sum(payload)
	tag := hex.EncodeToString(digest[:])

	return &tacticsData{
		tactics: tactics,
		payload: payload,
		tag:     tag,
	}, nil
}

// GetTactics assembles and returns tactics data for a client with the
// specified GeoIP, API parameter, and speed test attributes.
//
// The tactics return value may be nil.
//
// Callers must not mutate returned tactics data, which is cached.
func (server *Server) getTactics(
	includeServerSideOnly bool,
	geoIPData common.GeoIPData,
	apiParams common.APIParameters) (*tacticsData, error) {

	server.ReloadableFile.RLock()
	defer server.ReloadableFile.RUnlock()

	if !server.loaded {
		// No tactics configuration was loaded.
		return nil, nil
	}

	// Two passes are performed, one to get the list of matching filters, and
	// then, if no merged tactics data is found for that filter match set,
	// another pass to merge all the tactics parameters.

	var aggregatedValues map[string]int
	filterMatchCount := 0

	// Use the filterMatches buffer pool to avoid an allocation per getTactics
	// call.
	b := server.filterMatches.Get().(*[]bool)
	filterMatches := *b
	clear(filterMatches)
	defer server.filterMatches.Put(b)

	for filterIndex, filteredTactics := range server.FilteredTactics {

		filterMatches[filterIndex] = false

		if len(filteredTactics.Filter.Regions) > 0 {
			if filteredTactics.Filter.regionLookup != nil {
				if !filteredTactics.Filter.regionLookup[geoIPData.Country] {
					continue
				}
			} else {
				if !common.Contains(filteredTactics.Filter.Regions, geoIPData.Country) {
					continue
				}
			}
		}

		if len(filteredTactics.Filter.ISPs) > 0 {
			if filteredTactics.Filter.ispLookup != nil {
				if !filteredTactics.Filter.ispLookup[geoIPData.ISP] {
					continue
				}
			} else {
				if !common.Contains(filteredTactics.Filter.ISPs, geoIPData.ISP) {
					continue
				}
			}
		}

		if len(filteredTactics.Filter.ASNs) > 0 {
			if filteredTactics.Filter.asnLookup != nil {
				if !filteredTactics.Filter.asnLookup[geoIPData.ASN] {
					continue
				}
			} else {
				if !common.Contains(filteredTactics.Filter.ASNs, geoIPData.ASN) {
					continue
				}
			}
		}

		if len(filteredTactics.Filter.Cities) > 0 {
			if filteredTactics.Filter.cityLookup != nil {
				if !filteredTactics.Filter.cityLookup[geoIPData.City] {
					continue
				}
			} else {
				if !common.Contains(filteredTactics.Filter.Cities, geoIPData.City) {
					continue
				}
			}
		}

		if filteredTactics.Filter.APIParameters != nil {
			mismatch := false
			for name, values := range filteredTactics.Filter.APIParameters {
				clientValue, err := getStringRequestParam(apiParams, name)
				if err != nil || !common.ContainsWildcard(values, clientValue) {
					mismatch = true
					break
				}
			}
			if mismatch {
				continue
			}
		}

		if filteredTactics.Filter.MinClientVersion != nil ||
			filteredTactics.Filter.MaxClientVersion != nil {

			clientVersion, err := getIntStringRequestParam(
				apiParams, protocol.PSIPHON_API_HANDSHAKE_CLIENT_VERSION)
			if err != nil {
				continue
			}

			if filteredTactics.Filter.MinClientVersion != nil &&
				clientVersion < *filteredTactics.Filter.MinClientVersion {
				continue
			}

			if filteredTactics.Filter.MaxClientVersion != nil &&
				clientVersion > *filteredTactics.Filter.MaxClientVersion {
				continue
			}
		}

		if filteredTactics.Filter.SpeedTestRTTMilliseconds != nil {

			var speedTestSamples []SpeedTestSample
			err := getJSONRequestParam(apiParams, SPEED_TEST_SAMPLES_PARAMETER_NAME, &speedTestSamples)

			if err != nil {
				// TODO: log speed test parameter errors?
				// This API param is not explicitly validated elsewhere.
				continue
			}

			// As there must be at least one Range bound, there must be data to aggregate.
			if len(speedTestSamples) == 0 {
				continue
			}

			if aggregatedValues == nil {
				aggregatedValues = make(map[string]int)
			}

			// Note: here we could filter out outliers such as samples that are unusually old
			// or client/endPoint region pair too distant.

			// aggregate may mutate (sort) the speedTestSamples slice.
			value := aggregate(
				filteredTactics.Filter.SpeedTestRTTMilliseconds.Aggregation,
				speedTestSamples,
				aggregatedValues)

			if filteredTactics.Filter.SpeedTestRTTMilliseconds.AtLeast != nil &&
				value < *filteredTactics.Filter.SpeedTestRTTMilliseconds.AtLeast {
				continue
			}
			if filteredTactics.Filter.SpeedTestRTTMilliseconds.AtMost != nil &&
				value > *filteredTactics.Filter.SpeedTestRTTMilliseconds.AtMost {
				continue
			}
		}

		filterMatchCount += 1
		filterMatches[filterIndex] = true

		// Continue to check for more matches. Last matching tactics filter
		// has priority for any field.
	}

	// For any filter match set, the merged tactics parameters are the same,
	// so the resulting merge is cached, along with the JSON encoding of the
	// payload and hash tag. This cache reduces, for repeated tactics
	// requests, heavy allocations from the JSON marshal and CPU load from
	// both the marshal and hashing the marshal result.
	//
	// getCacheKey still allocates a strings.Builder buffer.
	//
	// TODO: log cache metrics; similar to what is done in
	// psiphon/server.ServerTacticsParametersCache.GetMetrics.

	cacheKey := getCacheKey(includeServerSideOnly, filterMatchCount > 0, filterMatches)

	cacheValue, ok := server.cachedTacticsData.Get(cacheKey)
	if ok {
		return cacheValue.(*tacticsData), nil
	}

	tactics := server.DefaultTactics.clone(includeServerSideOnly)
	if filterMatchCount > 0 {
		for filterIndex, filteredTactics := range server.FilteredTactics {
			if filterMatches[filterIndex] {
				tactics.merge(includeServerSideOnly, &filteredTactics.Tactics)
			}
		}
	}

	// See Tactics.Probability doc comment.
	tactics.Probability = 1.0

	tacticsData, err := newTacticsData(tactics)
	if err != nil {
		return nil, errors.Trace(err)
	}

	server.cachedTacticsData.Set(cacheKey, tacticsData, 0)

	return tacticsData, nil
}

func getCacheKey(
	includeServerSideOnly bool, hasFilterMatches bool, filterMatches []bool) string {

	prefix := "0-"
	if includeServerSideOnly {
		prefix = "1-"
	}

	// hasFilterMatches allows for skipping the strings.Builder setup and loop
	// entirely.
	if !hasFilterMatches {
		return prefix
	}

	var b strings.Builder
	_, _ = b.WriteString(prefix)
	for filterIndex, match := range filterMatches {
		if match {
			fmt.Fprintf(&b, "%x-", filterIndex)
		}
	}

	return b.String()
}

// TODO: refactor this copy of psiphon/server.getStringRequestParam into common?
func getStringRequestParam(apiParams common.APIParameters, name string) (string, error) {
	if apiParams[name] == nil {
		return "", errors.Tracef("missing param: %s", name)
	}
	value, ok := apiParams[name].(string)
	if !ok {
		return "", errors.Tracef("invalid param: %s", name)
	}
	return value, nil
}

// TODO: refactor this copy of psiphon/server.getIntStringRequestParam into common?
func getIntStringRequestParam(params common.APIParameters, name string) (int, error) {
	if params[name] == nil {
		return 0, errors.Tracef("missing param: %s", name)
	}
	valueStr, ok := params[name].(string)
	if !ok {
		return 0, errors.Tracef("invalid param: %s", name)
	}
	value, err := strconv.Atoi(valueStr)
	if !ok {
		return 0, errors.Trace(err)
	}
	return value, nil
}

func getJSONRequestParam(apiParams common.APIParameters, name string, value interface{}) error {
	if apiParams[name] == nil {
		return errors.Tracef("missing param: %s", name)
	}

	// Remarshal the parameter from common.APIParameters, as the initial API parameter
	// unmarshal will not have known the correct target type. I.e., instead of doing
	// unmarshal-into-struct, common.APIParameters will have an unmarshal-into-interface
	// value as described here: https://golang.org/pkg/encoding/json/#Unmarshal.

	jsonValue, err := json.Marshal(apiParams[name])
	if err != nil {
		return errors.Trace(err)
	}
	err = json.Unmarshal(jsonValue, value)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

// aggregate may mutate (sort) the speedTestSamples slice.
func aggregate(
	aggregation string,
	speedTestSamples []SpeedTestSample,
	aggregatedValues map[string]int) int {

	// Aggregated values are memoized to save recalculating for each filter.
	if value, ok := aggregatedValues[aggregation]; ok {
		return value
	}

	var value int

	switch aggregation {
	case AGGREGATION_MINIMUM:
		value = minimumSampleRTTMilliseconds(speedTestSamples)
	case AGGREGATION_MAXIMUM:
		value = maximumSampleRTTMilliseconds(speedTestSamples)
	case AGGREGATION_MEDIAN:
		value = medianSampleRTTMilliseconds(speedTestSamples)
	default:
		return 0
	}

	aggregatedValues[aggregation] = value
	return value
}

func minimumSampleRTTMilliseconds(samples []SpeedTestSample) int {

	if len(samples) == 0 {
		return 0
	}
	min := 0
	for i := 1; i < len(samples); i++ {
		if samples[i].RTTMilliseconds < samples[min].RTTMilliseconds {
			min = i
		}
	}
	return samples[min].RTTMilliseconds
}

func maximumSampleRTTMilliseconds(samples []SpeedTestSample) int {

	if len(samples) == 0 {
		return 0
	}
	max := 0
	for i := 1; i < len(samples); i++ {
		if samples[i].RTTMilliseconds > samples[max].RTTMilliseconds {
			max = i
		}
	}
	return samples[max].RTTMilliseconds
}

func medianSampleRTTMilliseconds(samples []SpeedTestSample) int {

	if len(samples) == 0 {
		return 0
	}

	// This in-place sort mutates the input slice.
	sort.Slice(
		samples,
		func(i, j int) bool {
			return samples[i].RTTMilliseconds < samples[j].RTTMilliseconds
		})

	// See: https://en.wikipedia.org/wiki/Median#Easy_explanation_of_the_sample_median

	mid := len(samples) / 2

	if len(samples)%2 == 1 {
		return samples[mid].RTTMilliseconds
	}

	return (samples[mid-1].RTTMilliseconds + samples[mid].RTTMilliseconds) / 2
}

func (t *Tactics) clone(includeServerSideOnly bool) *Tactics {

	u := &Tactics{
		TTL: t.TTL,
	}

	// Note: there is no deep copy of parameter values; the the returned
	// Tactics shares memory with the original and it individual parameters
	// should not be modified.
	if t.Parameters != nil {
		u.Parameters = make(map[string]interface{})
		for k, v := range t.Parameters {
			if includeServerSideOnly || !parameters.IsServerSideOnly(k) {
				u.Parameters[k] = v
			}
		}
	}

	return u
}

func (t *Tactics) merge(includeServerSideOnly bool, u *Tactics) {

	if u.TTL != "" {
		t.TTL = u.TTL
	}

	// Note: there is no deep copy of parameter values; the the returned
	// Tactics shares memory with the original and its individual parameters
	// should not be modified.
	if u.Parameters != nil {
		if t.Parameters == nil {
			t.Parameters = make(map[string]interface{})
		}
		for k, v := range u.Parameters {
			if includeServerSideOnly || !parameters.IsServerSideOnly(k) {
				t.Parameters[k] = v
			}
		}
	}
}

// HandleEndPoint routes the request to either handleSpeedTestRequest
// or handleTacticsRequest; or returns false if not handled.
func (server *Server) HandleEndPoint(
	endPoint string,
	geoIPData common.GeoIPData,
	w http.ResponseWriter,
	r *http.Request) bool {

	server.ReloadableFile.RLock()
	loaded := server.loaded
	hasRequestKeys := len(server.RequestPublicKey) > 0
	server.ReloadableFile.RUnlock()

	if !loaded || !hasRequestKeys {
		// No tactics configuration was loaded, or the configuration contained
		// no key material for tactics requests.
		return false
	}

	switch endPoint {
	case SPEED_TEST_END_POINT:
		server.handleSpeedTestRequest(geoIPData, w, r)
		return true
	case TACTICS_END_POINT:
		server.handleTacticsRequest(geoIPData, w, r)
		return true
	default:
		return false
	}
}

func (server *Server) handleSpeedTestRequest(
	_ common.GeoIPData, w http.ResponseWriter, r *http.Request) {

	_, err := ioutil.ReadAll(http.MaxBytesReader(w, r.Body, MAX_REQUEST_BODY_SIZE))
	if err != nil {
		server.logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("failed to read request body")
		common.TerminateHTTPConnection(w, r)
		return
	}

	response, err := MakeSpeedTestResponse(
		SPEED_TEST_PADDING_MIN_SIZE, SPEED_TEST_PADDING_MAX_SIZE)
	if err != nil {
		server.logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("failed to make response")
		common.TerminateHTTPConnection(w, r)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(response)
	if err != nil {
		server.logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("failed to write response")
		common.TerminateHTTPConnection(w, r)
		return
	}
}

func (server *Server) handleTacticsRequest(
	geoIPData common.GeoIPData, w http.ResponseWriter, r *http.Request) {

	server.ReloadableFile.RLock()
	requestPrivateKey := server.RequestPrivateKey
	requestObfuscatedKey := server.RequestObfuscatedKey
	server.ReloadableFile.RUnlock()

	// Read, decode, and unbox request payload.

	boxedRequest, err := ioutil.ReadAll(http.MaxBytesReader(w, r.Body, MAX_REQUEST_BODY_SIZE))
	if err != nil {
		server.logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("failed to read request body")
		common.TerminateHTTPConnection(w, r)
		return
	}

	var apiParams common.APIParameters
	bundledPeerPublicKey, err := unboxPayload(
		TACTICS_REQUEST_NONCE,
		nil,
		requestPrivateKey,
		requestObfuscatedKey,
		boxedRequest,
		&apiParams)
	if err != nil {
		server.logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("failed to unbox request")
		common.TerminateHTTPConnection(w, r)
		return
	}

	err = server.apiParameterValidator(apiParams)
	if err != nil {
		server.logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("invalid request parameters")
		common.TerminateHTTPConnection(w, r)
		return
	}

	tacticsPayload, err := server.GetTacticsPayload(geoIPData, apiParams)
	if err == nil && tacticsPayload == nil {
		err = errors.TraceNew("unexpected missing tactics payload")
	}
	if err != nil {
		server.logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("failed to get tactics")
		common.TerminateHTTPConnection(w, r)
		return
	}

	// Marshal, box, and write response payload.

	boxedResponse, err := boxPayload(
		TACTICS_RESPONSE_NONCE,
		bundledPeerPublicKey,
		requestPrivateKey,
		requestObfuscatedKey,
		nil,
		tacticsPayload)
	if err != nil {
		server.logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("failed to box response")
		common.TerminateHTTPConnection(w, r)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(boxedResponse)
	if err != nil {
		server.logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("failed to write response")
		common.TerminateHTTPConnection(w, r)
		return
	}
	// Log a metric.

	logFields := server.logFieldFormatter("", geoIPData, apiParams)

	logFields[NEW_TACTICS_TAG_LOG_FIELD_NAME] = tacticsPayload.Tag
	logFields[IS_TACTICS_REQUEST_LOG_FIELD_NAME] = true

	server.logger.LogMetric(TACTICS_METRIC_EVENT_NAME, logFields)
}

// ObfuscatedRoundTripper performs a round trip to the specified endpoint,
// sending the request body and returning the response body, with an
// obfuscation layer applied to the endpoint value. The context may be used
// to set a timeout or cancel the round trip.
//
// The Psiphon client provides a ObfuscatedRoundTripper using MeekConn. The
// client will handle connection details including server selection, dialing
// details including device binding and upstream proxy, etc.
type ObfuscatedRoundTripper func(
	ctx context.Context,
	endPoint string,
	requestBody []byte) ([]byte, error)

// Storer provides a facility to persist tactics and speed test data.
type Storer interface {
	SetTacticsRecord(networkID string, record []byte) error
	GetTacticsRecord(networkID string) ([]byte, error)
	SetSpeedTestSamplesRecord(networkID string, record []byte) error
	GetSpeedTestSamplesRecord(networkID string) ([]byte, error)
}

// SetTacticsAPIParameters populates apiParams with the additional
// parameters for tactics. This is used by the Psiphon client when
// preparing its handshake request.
func SetTacticsAPIParameters(
	storer Storer,
	networkID string,
	apiParams common.APIParameters) error {

	// TODO: store the tag in its own record to avoid loading the whole tactics record?

	record, err := getStoredTacticsRecord(storer, networkID)
	if err != nil {
		return errors.Trace(err)
	}

	speedTestSamples, err := getSpeedTestSamples(storer, networkID)
	if err != nil {
		return errors.Trace(err)
	}

	apiParams[STORED_TACTICS_TAG_PARAMETER_NAME] = record.Tag
	apiParams[SPEED_TEST_SAMPLES_PARAMETER_NAME] = speedTestSamples

	return nil
}

// HandleTacticsPayload updates the stored tactics with the given payload. If
// the payload has a new tag/tactics, this is stored and a new expiry time is
// set. If the payload has the same tag, the existing tactics are retained,
// the expiry is extended using the previous TTL, and a nil record is
// rerturned.
//
// HandleTacticsPayload is called by the Psiphon client to handle the tactics
// payload in the API handshake and inproxy broker responses. As the Psiphon
// client has already called UseStoredTactics/FetchTactics and applied
// tactics, the nil record return value allows the caller to skip an
// unnecessary tactics parameters application.
func HandleTacticsPayload(
	storer Storer,
	networkID string,
	payload *Payload) (*Record, error) {

	// Note: since, in the client, a tactics request and a handshake
	// request could be in flight concurrently, there exists a possibility
	// that one clobbers the others result, and the clobbered result may
	// be newer.
	//
	// However:
	// - in the Storer, the tactics record is a single key/value, so its
	//   elements are updated atomically;
	// - the client Controller typically stops/aborts any outstanding
	//   tactics request before the handshake
	// - this would have to be concurrent with a tactics configuration hot
	//   reload on the server
	// - old and new tactics should both be valid

	if payload == nil {
		return nil, errors.TraceNew("unexpected nil payload")
	}

	record, err := getStoredTacticsRecord(storer, networkID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	newTactics, err := applyTacticsPayload(storer, networkID, record, payload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Store the tactics record, which may contain new tactics, and always
	// contains an extended TTL.
	//
	// TODO: if tags match, just set an expiry record, not the whole tactics
	// record?

	err = setStoredTacticsRecord(storer, networkID, record)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if !newTactics {
		// Don't return a tactics record when the tactics have not changed.
		record = nil
	}

	return record, nil
}

// UseStoredTactics checks for an unexpired stored tactics record for the
// given network ID that may be used immediately. When there is no error
// and the record is nil, the caller should proceed with FetchTactics.
//
// When used, Record.Tag should be reported as the applied tactics tag.
func UseStoredTactics(
	storer Storer, networkID string) (*Record, error) {

	record, err := getStoredTacticsRecord(storer, networkID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if record.Tag != "" && record.Expiry.After(time.Now().UTC()) {
		return record, nil
	}

	return nil, nil
}

// FetchTactics performs a tactics request. When there are no stored
// speed test samples for the network ID, a speed test request is
// performed immediately before the tactics request, using the same
// ObfuscatedRoundTripper.
//
// The ObfuscatedRoundTripper transport should be established in advance, so
// that calls to ObfuscatedRoundTripper don't take additional time in TCP,
// TLS, etc. handshakes.
//
// The caller should first call UseStoredTactics and skip FetchTactics
// when there is an unexpired stored tactics record available. The
// caller is expected to set any overall timeout in the context input.
//
// Limitation: it is assumed that the network ID obtained from getNetworkID
// is the one that is active when the tactics request is received by the
// server. However, it is remotely possible to switch networks
// immediately after invoking the GetNetworkID callback and initiating
// the request. This is partially mitigated by rechecking the network ID
// after the request and failing if it differs from the initial network ID.
//
// FetchTactics modifies the apiParams input.
func FetchTactics(
	ctx context.Context,
	params *parameters.Parameters,
	storer Storer,
	getNetworkID func() string,
	apiParams common.APIParameters,
	endPointRegion string,
	endPointProtocol string,
	encodedRequestPublicKey string,
	encodedRequestObfuscatedKey string,
	obfuscatedRoundTripper ObfuscatedRoundTripper) (*Record, error) {

	networkID := getNetworkID()

	record, err := getStoredTacticsRecord(storer, networkID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	speedTestSamples, err := getSpeedTestSamples(storer, networkID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Perform a speed test when there are no samples.

	if len(speedTestSamples) == 0 {

		p := params.Get()
		request := prng.Padding(
			p.Int(parameters.SpeedTestPaddingMinBytes),
			p.Int(parameters.SpeedTestPaddingMaxBytes))

		startTime := time.Now()

		response, err := obfuscatedRoundTripper(ctx, SPEED_TEST_END_POINT, request)

		elapsedTime := time.Since(startTime)

		if err != nil {
			return nil, errors.Trace(err)
		}

		if networkID != getNetworkID() {
			return nil, errors.TraceNew("network ID changed")
		}

		err = AddSpeedTestSample(
			params,
			storer,
			networkID,
			endPointRegion,
			endPointProtocol,
			elapsedTime,
			request,
			response)
		if err != nil {
			return nil, errors.Trace(err)
		}

		speedTestSamples, err = getSpeedTestSamples(storer, networkID)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// Perform the tactics request.

	apiParams[STORED_TACTICS_TAG_PARAMETER_NAME] = record.Tag
	apiParams[SPEED_TEST_SAMPLES_PARAMETER_NAME] = speedTestSamples

	requestPublicKey, err := base64.StdEncoding.DecodeString(encodedRequestPublicKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	requestObfuscatedKey, err := base64.StdEncoding.DecodeString(encodedRequestObfuscatedKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	ephemeralPublicKey, ephemeralPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.Trace(err)
	}

	boxedRequest, err := boxPayload(
		TACTICS_REQUEST_NONCE,
		requestPublicKey,
		ephemeralPrivateKey[:],
		requestObfuscatedKey,
		ephemeralPublicKey[:],
		&apiParams)
	if err != nil {
		return nil, errors.Trace(err)
	}

	boxedResponse, err := obfuscatedRoundTripper(ctx, TACTICS_END_POINT, boxedRequest)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if networkID != getNetworkID() {
		return nil, errors.TraceNew("network ID changed")
	}

	// Process and store the response payload.

	var payload *Payload

	_, err = unboxPayload(
		TACTICS_RESPONSE_NONCE,
		requestPublicKey,
		ephemeralPrivateKey[:],
		requestObfuscatedKey,
		boxedResponse,
		&payload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	_, err = applyTacticsPayload(storer, networkID, record, payload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = setStoredTacticsRecord(storer, networkID, record)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return record, nil
}

// MakeSpeedTestResponse creates a speed test response prefixed
// with a timestamp and followed by random padding. The timestamp
// enables the client performing the speed test to record the
// sample time with an accurate server clock; the random padding
// is to frustrate fingerprinting.
// The speed test timestamp is truncated as a privacy measure.
func MakeSpeedTestResponse(minPadding, maxPadding int) ([]byte, error) {

	// MarshalBinary encoding (version 1) is 15 bytes:
	// https://github.com/golang/go/blob/release-branch.go1.9/src/time/time.go#L1112

	timestamp, err := time.Now().UTC().Truncate(1 * time.Hour).MarshalBinary()
	if err == nil && len(timestamp) > 255 {
		err = fmt.Errorf("unexpected marshaled time size: %d", len(timestamp))
	}
	if err != nil {
		return nil, errors.Trace(err)
	}

	randomPadding := prng.Padding(minPadding, maxPadding)
	// On error, proceed without random padding.
	// TODO: log error, even if proceeding?

	response := make([]byte, 0, 1+len(timestamp)+len(randomPadding))

	response = append(response, byte(len(timestamp)))
	response = append(response, timestamp...)
	response = append(response, randomPadding...)

	return response, nil
}

// AddSpeedTestSample stores a new speed test sample. A maximum of
// SpeedTestMaxSampleCount samples per network ID are stored, so once
// that limit is reached, the oldest samples are removed to make room
// for the new sample.
func AddSpeedTestSample(
	params *parameters.Parameters,
	storer Storer,
	networkID string,
	endPointRegion string,
	endPointProtocol string,
	elaspedTime time.Duration,
	request []byte,
	response []byte) error {

	if len(response) < 1 {
		return errors.TraceNew("unexpected empty response")
	}
	timestampLength := int(response[0])
	if len(response) < 1+timestampLength {
		return errors.Tracef(
			"unexpected response shorter than timestamp size %d", timestampLength)
	}
	var timestamp time.Time
	err := timestamp.UnmarshalBinary(response[1 : 1+timestampLength])
	if err != nil {
		return errors.Trace(err)
	}

	sample := SpeedTestSample{
		Timestamp:        timestamp,
		EndPointRegion:   endPointRegion,
		EndPointProtocol: endPointProtocol,
		RTTMilliseconds:  int(elaspedTime / time.Millisecond),
		BytesUp:          len(request),
		BytesDown:        len(response),
	}

	maxCount := params.Get().Int(parameters.SpeedTestMaxSampleCount)
	if maxCount == 0 {
		return errors.TraceNew("speed test max sample count is 0")
	}

	speedTestSamples, err := getSpeedTestSamples(storer, networkID)
	if err != nil {
		return errors.Trace(err)
	}

	if speedTestSamples == nil {
		speedTestSamples = make([]SpeedTestSample, 0)
	}

	if len(speedTestSamples)+1 > maxCount {
		speedTestSamples = speedTestSamples[len(speedTestSamples)+1-maxCount:]
	}
	speedTestSamples = append(speedTestSamples, sample)

	record, err := json.Marshal(speedTestSamples)
	if err != nil {
		return errors.Trace(err)
	}

	err = storer.SetSpeedTestSamplesRecord(networkID, record)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func getSpeedTestSamples(
	storer Storer, networkID string) ([]SpeedTestSample, error) {

	record, err := storer.GetSpeedTestSamplesRecord(networkID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if record == nil {
		return nil, nil
	}

	var speedTestSamples []SpeedTestSample
	err = json.Unmarshal(record, &speedTestSamples)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return speedTestSamples, nil
}

func getStoredTacticsRecord(
	storer Storer, networkID string) (*Record, error) {

	marshaledRecord, err := storer.GetTacticsRecord(networkID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if marshaledRecord == nil {
		return &Record{}, nil
	}

	var record *Record
	err = json.Unmarshal(marshaledRecord, &record)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if record == nil {
		record = &Record{}
	}

	return record, nil
}

func applyTacticsPayload(
	storer Storer,
	networkID string,
	record *Record,
	payload *Payload) (bool, error) {

	newTactics := false

	if payload.Tag == "" {
		return newTactics, errors.TraceNew("invalid tag")
	}

	// Replace the tactics data when the tags differ.

	if payload.Tag != record.Tag {

		// There is a potential race condition that may arise with multiple
		// concurrent requests which may return tactics, such as in-proxy
		// proxy announcements. In this scenario, an in-flight request
		// matches the existing current tactics tag; then a concurrent
		// request is sent while new tactics become available and its
		// response returns new tactics and a new tag; the client applies the
		// new tags and tactics; then, finally, the response for the first
		// request arrives with a now apparently different tag -- the
		// original tag -- but no tactics payload. In this case, simply fail
		// the apply operation.

		// A nil payload.Tactics, of type json.RawMessage, can be serialized
		// as the JSON "null".
		if payload.Tactics == nil ||
			bytes.Equal(payload.Tactics, []byte("null")) {
			return newTactics, errors.TraceNew("missing tactics")
		}

		record.Tag = payload.Tag
		record.Tactics = Tactics{}
		err := json.Unmarshal(payload.Tactics, &record.Tactics)
		if err != nil {
			return newTactics, errors.Trace(err)
		}

		newTactics = true
	}

	// Note: record.Tactics.TTL is validated by server
	ttl, err := time.ParseDuration(record.Tactics.TTL)
	if err != nil {
		return newTactics, errors.Trace(err)
	}

	if ttl <= 0 {
		return newTactics, errors.TraceNew("invalid TTL")
	}

	// Set or extend the expiry.

	record.Expiry = time.Now().UTC().Add(ttl)

	return newTactics, nil
}

func setStoredTacticsRecord(
	storer Storer,
	networkID string,
	record *Record) error {

	marshaledRecord, err := json.Marshal(record)
	if err != nil {
		return errors.Trace(err)
	}

	err = storer.SetTacticsRecord(networkID, marshaledRecord)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func boxPayload(
	nonce, peerPublicKey, privateKey, obfuscatedKey, bundlePublicKey []byte,
	payload interface{}) ([]byte, error) {

	if len(nonce) > 24 ||
		len(peerPublicKey) != 32 ||
		len(privateKey) != 32 {
		return nil, errors.TraceNew("unexpected box key length")
	}

	marshaledPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var nonceArray [24]byte
	copy(nonceArray[:], nonce)

	var peerPublicKeyArray, privateKeyArray [32]byte
	copy(peerPublicKeyArray[:], peerPublicKey)
	copy(privateKeyArray[:], privateKey)

	box := box.Seal(nil, marshaledPayload, &nonceArray, &peerPublicKeyArray, &privateKeyArray)

	if bundlePublicKey != nil {
		bundledBox := make([]byte, 32+len(box))
		copy(bundledBox[0:32], bundlePublicKey[0:32])
		copy(bundledBox[32:], box)
		box = bundledBox
	}

	// TODO: replay tactics request padding?
	paddingPRNGSeed, err := prng.NewSeed()
	if err != nil {
		return nil, errors.Trace(err)
	}

	maxPadding := TACTICS_PADDING_MAX_SIZE

	obfuscator, err := obfuscator.NewClientObfuscator(
		&obfuscator.ObfuscatorConfig{
			Keyword:         string(obfuscatedKey),
			PaddingPRNGSeed: paddingPRNGSeed,
			MaxPadding:      &maxPadding})
	if err != nil {
		return nil, errors.Trace(err)
	}

	obfuscatedBox, _ := obfuscator.SendPreamble()
	seedLen := len(obfuscatedBox)

	obfuscatedBox = append(obfuscatedBox, box...)
	obfuscator.ObfuscateClientToServer(obfuscatedBox[seedLen:])

	return obfuscatedBox, nil
}

// unboxPayload mutates obfuscatedBoxedPayload by deobfuscating in-place.
func unboxPayload(
	nonce, peerPublicKey, privateKey, obfuscatedKey, obfuscatedBoxedPayload []byte,
	payload interface{}) ([]byte, error) {

	if len(nonce) > 24 ||
		(peerPublicKey != nil && len(peerPublicKey) != 32) ||
		len(privateKey) != 32 {
		return nil, errors.TraceNew("unexpected box key length")
	}

	obfuscatedReader := bytes.NewReader(obfuscatedBoxedPayload[:])

	obfuscator, err := obfuscator.NewServerObfuscator(
		&obfuscator.ObfuscatorConfig{Keyword: string(obfuscatedKey)},
		"",
		obfuscatedReader)
	if err != nil {
		return nil, errors.Trace(err)
	}

	seedLen, err := obfuscatedReader.Seek(0, 1)
	if err != nil {
		return nil, errors.Trace(err)
	}

	boxedPayload := obfuscatedBoxedPayload[seedLen:]
	obfuscator.ObfuscateClientToServer(boxedPayload)

	var nonceArray [24]byte
	copy(nonceArray[:], nonce)

	var peerPublicKeyArray, privateKeyArray [32]byte
	copy(privateKeyArray[:], privateKey)

	var bundledPeerPublicKey []byte

	if peerPublicKey != nil {
		copy(peerPublicKeyArray[:], peerPublicKey)
	} else {
		if len(boxedPayload) < 32 {
			return nil, errors.TraceNew("unexpected box size")
		}
		bundledPeerPublicKey = boxedPayload[0:32]
		copy(peerPublicKeyArray[:], bundledPeerPublicKey)
		boxedPayload = boxedPayload[32:]
	}

	marshaledPayload, ok := box.Open(nil, boxedPayload, &nonceArray, &peerPublicKeyArray, &privateKeyArray)
	if !ok {
		return nil, errors.TraceNew("invalid box")
	}

	err = json.Unmarshal(marshaledPayload, payload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return bundledPeerPublicKey, nil
}
