package psiphon

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/cespare/xxhash"
)

// frontedHTTPClientInstance contains the fronted HTTP dial parameters required
// to create a net/http.Client, which is configured to use domain fronting.
// frontedHTTPClientInstance implements HTTP client dial replay.
type frontedHTTPClientInstance struct {
	frontedHTTPDialParameters     *frontedHTTPDialParameters
	networkID                     string
	replayEnabled                 bool
	replayRetainFailedProbability float64
	replayUpdateFrequency         time.Duration

	mutex           sync.Mutex
	lastStoreReplay time.Time
}

// newFrontedHTTPClientInstance creates a new frontedHTTPClientInstance.
// newFrontedHTTPClientInstance does not perform any network operations; the
// new frontedHTTPClientInstance is initialized when used for a round
// trip.
func newFrontedHTTPClientInstance(
	config *Config,
	tunnel *Tunnel,
	frontingSpecs parameters.FrontingSpecs,
	selectedFrontingProviderID func(string),
	useDeviceBinder,
	skipVerify,
	disableSystemRootCAs,
	payloadSecure bool,
) (*frontedHTTPClientInstance, error) {

	// This function duplicates some code from NewInproxyBrokerClientInstance.
	//
	// TODO: merge common functionality?

	p := config.GetParameters().Get()
	defer p.Close()

	// Shuffle fronting specs, for random load balancing. Fronting specs with
	// available dial parameter replay data are preferred.

	permutedIndexes := prng.Perm(len(frontingSpecs))
	shuffledFrontingSpecs := make(parameters.FrontingSpecs, len(frontingSpecs))
	for i, index := range permutedIndexes {
		shuffledFrontingSpecs[i] = frontingSpecs[index]
	}
	frontingSpecs = shuffledFrontingSpecs

	// Replay fronted HTTP dial parameters.

	var spec *parameters.FrontingSpec
	var dialParams *frontedHTTPDialParameters

	// Replay is disabled when the TTL, TransferURLReplayDialParametersTTL,
	// is 0.
	now := time.Now()
	ttl := p.Duration(parameters.TransferURLReplayDialParametersTTL)
	networkID := config.GetNetworkID()

	// Replay is disabled if there is an active tunnel.
	replayEnabled := tunnel == nil &&
		ttl > 0 &&
		!config.DisableReplay &&
		prng.FlipWeightedCoin(p.Float(parameters.TransferURLReplayDialParametersProbability))

	if replayEnabled {
		selectFirstCandidate := false
		var err error
		spec, dialParams, err =
			SelectCandidateWithNetworkReplayParameters[parameters.FrontingSpec, frontedHTTPDialParameters](
				networkID,
				selectFirstCandidate,
				frontingSpecs,
				func(spec *parameters.FrontingSpec) string { return spec.FrontingProviderID },
				func(spec *parameters.FrontingSpec, dialParams *frontedHTTPDialParameters) bool {
					// Replay the successful fronting spec, if present, by
					// comparing its hash with that of the candidate.
					return dialParams.LastUsedTimestamp.After(now.Add(-ttl)) &&
						bytes.Equal(dialParams.LastUsedFrontingSpecHash, hashFrontingSpec(spec))
				})
		if err != nil {
			NoticeWarning("SelectCandidateWithNetworkReplayParameters failed: %v", errors.Trace(err))
			// Continue without replay
		}
	}

	// Select the first fronting spec in the shuffle when replay is not enabled
	// or in case SelectCandidateWithNetworkReplayParameters fails.
	if spec == nil {
		spec = frontingSpecs[prng.Intn(len(frontingSpecs)-1)]
	}

	// Generate new fronted HTTP dial parameters if not replaying. Later,
	// isReplay is used to report the replay metric.

	isReplay := dialParams != nil

	if !isReplay {
		var err error
		dialParams, err = makeFrontedHTTPDialParameters(
			config,
			p,
			tunnel,
			spec,
			selectedFrontingProviderID,
			useDeviceBinder,
			skipVerify,
			disableSystemRootCAs,
			payloadSecure)
		if err != nil {
			return nil, errors.Trace(err)
		}
	} else {
		err := dialParams.prepareDialConfigs(
			config,
			p,
			isReplay,
			tunnel,
			useDeviceBinder,
			skipVerify,
			disableSystemRootCAs,
			payloadSecure)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	return &frontedHTTPClientInstance{
		networkID:                 networkID,
		frontedHTTPDialParameters: dialParams,
		replayEnabled:             replayEnabled,

		replayRetainFailedProbability: p.Float(parameters.TransferURLReplayRetainFailedProbability),
		replayUpdateFrequency:         p.Duration(parameters.TransferURLReplayUpdateFrequency),
	}, nil
}

// RoundTrip implements the http.RoundTripper interface. RoundTrip makes a
// domain fronted request to the meek server.
//
// Resources are cleaned up when the response body is closed.
func (f *frontedHTTPClientInstance) RoundTrip(request *http.Request) (*http.Response, error) {

	// This function duplicates some code from InproxyBrokerRoundTripper.RoundTrip,
	// which has a more thorough implementation.
	//
	// TODO: merge implementations or common functionality?

	// Use MeekConn to domain front requests.
	conn, err := DialMeek(
		request.Context(),
		f.frontedHTTPDialParameters.FrontedMeekDialParameters.meekConfig,
		f.frontedHTTPDialParameters.FrontedMeekDialParameters.dialConfig)
	if err != nil {
		if request.Context().Err() != context.Canceled {
			// DialMeek performs an initial TLS handshake. Clear replay
			// parameters on error, excluding a cancelled context as
			// happens on shutdown.
			f.frontedHTTPClientRoundTripperFailed()
		}
		return nil, errors.Trace(err)
	}

	response, err := conn.RoundTrip(request)
	if err != nil {
		if request.Context().Err() != context.Canceled {
			// Clear replay parameters on other round trip errors, including
			// TLS failures and client-side timeouts, but excluding a cancelled
			// context as happens on shutdown.
			f.frontedHTTPClientRoundTripperFailed()
		}
		return nil, errors.Trace(err)
	}

	// Do not read the response body into memory all at once because it may
	// be large. Instead allow the caller to stream the response.
	body := newMeekHTTPResponseReadCloser(conn, response.Body)

	// Clear replay parameters if there are any errors while reading from the
	// response body.
	response.Body = newFrontedHTTPClientResponseReadCloser(f, body)

	if response.StatusCode == http.StatusOK {
		f.frontedHTTPClientRoundTripperSucceeded()
	} else {
		// TODO: do not clear replay parameters on temporary round tripper
		// failures, see InproxyBrokerRoundTripper.RoundTrip.
		f.frontedHTTPClientRoundTripperFailed()
	}

	return response, nil
}

// meekHTTPResponseReadCloser wraps an http.Response.Body received over a
// frontedHTTPClientInstance in RoundTrip and exposes an io.ReadCloser.
// Replay parameters are cleared if there are any errors while reading from
// the response body.
type frontedHTTPClientResponseReadCloser struct {
	client       *frontedHTTPClientInstance
	responseBody io.ReadCloser
}

// newFrontedHTTPClientResponseReadCloser creates a frontedHTTPClientResponseReadCloser.
func newFrontedHTTPClientResponseReadCloser(
	client *frontedHTTPClientInstance,
	responseBody io.ReadCloser) *frontedHTTPClientResponseReadCloser {

	return &frontedHTTPClientResponseReadCloser{
		client:       client,
		responseBody: responseBody,
	}
}

// Read implements the io.Reader interface.
func (f *frontedHTTPClientResponseReadCloser) Read(p []byte) (n int, err error) {
	n, err = f.responseBody.Read(p)
	if err != nil {
		f.client.frontedHTTPClientRoundTripperFailed()
	}
	return n, err
}

// Read implements the io.Closer interface.
func (f *frontedHTTPClientResponseReadCloser) Close() error {
	return f.responseBody.Close()
}

// frontedHTTPClientRoundTripperSucceeded stores the current dial parameters
// for replay.
func (f *frontedHTTPClientInstance) frontedHTTPClientRoundTripperSucceeded() {

	// Note: duplicates code in BrokerClientRoundTripperSucceeded.

	f.mutex.Lock()
	defer f.mutex.Unlock()

	now := time.Now()
	if f.replayEnabled && now.Sub(f.lastStoreReplay) > f.replayUpdateFrequency {
		f.frontedHTTPDialParameters.LastUsedTimestamp = time.Now()

		replayID := f.frontedHTTPDialParameters.FrontedMeekDialParameters.FrontingProviderID

		err := SetNetworkReplayParameters[frontedHTTPDialParameters](
			f.networkID, replayID, f.frontedHTTPDialParameters)
		if err != nil {
			NoticeWarning("SetNetworkReplayParameters failed: %v", errors.Trace(err))
			// Continue without persisting replay changes.
		} else {
			f.lastStoreReplay = now
		}
	}
}

// frontedHTTPClientRoundTripperFailed clears replay parameters.
func (f *frontedHTTPClientInstance) frontedHTTPClientRoundTripperFailed() {

	// Note: duplicates code in BrokerClientRoundTripperFailed.

	f.mutex.Lock()
	defer f.mutex.Unlock()
	// Delete any persistent replay dial parameters. Unlike with the success
	// case, consecutive, repeated deletes shouldn't write to storage, so
	// they are not avoided.

	if f.replayEnabled &&
		!prng.FlipWeightedCoin(f.replayRetainFailedProbability) {

		// Limitation: there's a race condition with multiple
		// frontedHTTPClientInstances writing to the replay datastore, such as
		// in the case where there's a feedback upload running concurrently
		// with a server list download; this delete could potentially clobber a
		// concurrent fresh replay store after a success.
		//
		// TODO: add an additional storage key distinguisher for each instance?

		replayID := f.frontedHTTPDialParameters.FrontedMeekDialParameters.FrontingProviderID

		err := DeleteNetworkReplayParameters[frontedHTTPDialParameters](
			f.networkID, replayID)
		if err != nil {
			NoticeWarning("DeleteNetworkReplayParameters failed: %v", errors.Trace(err))
			// Continue without resetting replay.
		}
	}
}

// hashFrontingSpec hashes the fronting spec. The hash is used to detect when
// fronting spec tactics have changed.
func hashFrontingSpec(spec *parameters.FrontingSpec) []byte {
	var hash [8]byte
	binary.BigEndian.PutUint64(
		hash[:],
		uint64(xxhash.Sum64String(fmt.Sprintf("%+v", spec))))
	return hash[:]
}
