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

// Package osl implements the Obfuscated Server List (OSL) mechanism. This
// mechanism is a method of distributing server lists only to clients that
// demonstrate certain behavioral traits. Clients are seeded with Server
// List Obfuscation Keys (SLOKs) as they meet the configured criteria. These
// keys are stored and later combined to assemble keys to decrypt out-of-band
// distributed OSL files that contain server lists.
//
// This package contains the core routines used in psiphond (to track client
// traits and issue SLOKs), clients (to manage SLOKs and decrypt OSLs), and
// automation (to create OSLs for distribution).
package osl

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	std_errors "errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/nacl/secretbox"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/sss"
)

const (
	KEY_LENGTH_BYTES    = 32
	REGISTRY_FILENAME   = "osl-registry"
	OSL_FILENAME_FORMAT = "osl-%s"
)

// Config is an OSL configuration, which consists of a list of schemes.
// The Reload function supports hot reloading of rules data while the
// process is running.
type Config struct {
	common.ReloadableFile

	Schemes []*Scheme
}

// Scheme defines a OSL seeding and distribution strategy. SLOKs to
// decrypt OSLs are issued based on client network activity -- defined
// in the SeedSpecs -- and time. OSLs are created for periods of time
// and can be decrypted by clients that are seeded with a sufficient
// selection of SLOKs for that time period. Distribution of server
// entries to OSLs is delegated to automation.
type Scheme struct {

	// Epoch is the start time of the scheme, the start time of the
	// first OSL and when SLOKs will first be issued. It must be
	// specified in UTC and must be a multiple of SeedPeriodNanoseconds.
	Epoch string

	// PaveDataOSLCount indicates how many active OSLs GetPaveData should
	// return. Must be must be > 0 when using GetPaveData.
	PaveDataOSLCount int

	// Regions is a list of client country codes this scheme applies to.
	// If empty, the scheme applies to all regions.
	Regions []string

	// PropagationChannelIDs is a list of client propagtion channel IDs
	// this scheme applies to. Propagation channel IDs are an input
	// to SLOK key derivation.
	PropagationChannelIDs []string

	// MasterKey is the base random key used for SLOK key derivation. It
	// must be unique for each scheme. It must be 32 random bytes, base64
	// encoded.
	MasterKey []byte

	// SeedSpecs is the set of different client network activity patterns
	// that will result in issuing SLOKs. For a given time period, a distinct
	// SLOK is issued for each SeedSpec.
	// Duplicate subnets and ASNs may appear in multiple SeedSpecs.
	SeedSpecs []*SeedSpec

	// SeedSpecThreshold is the threshold scheme for combining SLOKs to
	// decrypt an OSL. For any fixed time period, at least K (threshold) of
	// N (total) SLOKs from the N SeedSpecs must be seeded for a client to be
	// able to reassemble the OSL key.
	// Limitation: thresholds must be at least 2.
	SeedSpecThreshold int

	// SeedPeriodNanoseconds is the time period granularity of SLOKs.
	// New SLOKs are issued every SeedPeriodNanoseconds. Client progress
	// towards activity levels is reset at the end of each period.
	SeedPeriodNanoseconds int64

	// KeySplits is the time period threshold scheme layered on top of the
	// SeedSpecThreshold scheme for combining SLOKs to decrypt an OSL.
	// There must be at least one level. For one level, any K (threshold) of
	// N (total) SeedSpec SLOK groups must be sufficiently seeded for a client
	// to be able to reassemble the OSL key. When an additional level is
	// specified, then K' of N' groups of N of K SeedSpec SLOK groups must be
	// sufficiently seeded. And so on. The first level in the list is the
	// lowest level. The time period for OSLs is determined by the totals in
	// the KeySplits.
	//
	// Example:
	//
	//   SeedSpecs = <3 specs>
	//   SeedSpecThreshold = 2
	//   SeedPeriodNanoseconds = 100,000,000 = 100 milliseconds
	//   SeedPeriodKeySplits = [{10, 7}, {60, 5}]
	//
	//   In this scheme, up to 3 distinct SLOKs, one per spec, are issued
	//   every 100 milliseconds.
	//
	//   Distinct OSLs are paved for every minute (60 seconds). Each OSL
	//   key is split such that, for those 60 seconds, a client must seed
	//   2/3 spec SLOKs for 7 of 10 consecutive 100 ms. time periods within
	//   a second, for any 5 of 60 seconds within the minute.
	//
	SeedPeriodKeySplits []KeySplit

	// The following fields are ephemeral state.

	epoch                 time.Time
	subnetLookups         []common.SubnetLookup
	derivedSLOKCacheMutex sync.RWMutex
	derivedSLOKCache      map[slokReference]*SLOK
}

// SeedSpec defines a client traffic pattern that results in a seeded SLOK.
// For each time period, a unique SLOK is issued to a client that meets the
// traffic levels specified in Targets. All upstream port forward traffic to
// UpstreamSubnets and UpstreamASNs are counted towards the targets.
//
// ID is a SLOK key derivation component and must be 32 random bytes, base64
// encoded. UpstreamSubnets is a list of CIDRs. UpstreamASNs is a list of
// ASNs. Description is not used; it's for JSON config file comments.
type SeedSpec struct {
	Description     string
	ID              []byte
	UpstreamSubnets []string
	UpstreamASNs    []string
	Targets         TrafficValues
}

// TrafficValues defines a client traffic level that seeds a SLOK.
// BytesRead and BytesWritten are the minimum bytes transferred counts to
// seed a SLOK. Both UDP and TCP data will be counted towards these totals.
// PortForwardDurationNanoseconds is the duration that a TCP or UDP port
// forward is active (not connected, in the UDP case). All threshold
// settings must be met to seed a SLOK; any threshold may be set to 0 to
// be trivially satisfied.
type TrafficValues struct {
	BytesRead                      int64
	BytesWritten                   int64
	PortForwardDurationNanoseconds int64
}

// KeySplit defines a secret key splitting scheme where the secret is split
// into n (total) shares and any K (threshold) of N shares must be known
// to recostruct the split secret.
type KeySplit struct {
	Total     int
	Threshold int
}

// ClientSeedState tracks the progress of a client towards seeding SLOKs
// across all schemes the client qualifies for.
type ClientSeedState struct {
	propagationChannelID string
	seedProgress         []*ClientSeedProgress
	mutex                sync.Mutex
	signalIssueSLOKs     chan struct{}
	issuedSLOKs          map[string]*SLOK
	payloadSLOKs         []*SLOK
}

// ClientSeedProgress tracks client progress towards seeding SLOKs for
// a particular scheme.
type ClientSeedProgress struct {
	// Note: 64-bit ints used with atomic operations are placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	progressSLOKTime int64
	scheme           *Scheme
	trafficProgress  []*TrafficValues
}

// ClientSeedPortForward map a client port forward, which is relaying
// traffic to a specific upstream address, to all seed state progress
// counters for SeedSpecs with subnets and ASNs containing the upstream address.
// As traffic is relayed through the port forwards, the bytes transferred
// and duration count towards the progress of these SeedSpecs and
// associated SLOKs.
type ClientSeedPortForward struct {
	state              *ClientSeedState
	progressReferences []progressReference
}

// progressReference points to a particular ClientSeedProgress and
// TrafficValues for to update with traffic events for a
// ClientSeedPortForward.
type progressReference struct {
	seedProgressIndex    int
	trafficProgressIndex int
}

// slokReference uniquely identifies a SLOK by specifying all the fields
// used to derive the SLOK secret key and ID.
// Note: SeedSpecID is not a []byte as slokReference is used as a map key.
type slokReference struct {
	PropagationChannelID string
	SeedSpecID           string
	Time                 time.Time
}

// SLOK is a seeded SLOK issued to a client. The client will store the
// SLOK in its local database; look it up by ID when checking which OSLs it
// can reassemble keys for; and use the key material to reassemble OSL
// file keys.
type SLOK struct {
	ID  []byte
	Key []byte
}

// SeedPayload is the list of seeded SLOKs sent to a client.
type SeedPayload struct {
	SLOKs []*SLOK
}

// NewConfig initializes a Config with the settings in the specified
// file.
func NewConfig(filename string) (*Config, error) {

	config := &Config{}

	config.ReloadableFile = common.NewReloadableFile(
		filename,
		true,
		func(fileContent []byte, _ time.Time) error {
			newConfig, err := LoadConfig(fileContent)
			if err != nil {
				return errors.Trace(err)
			}
			// Modify actual traffic rules only after validation
			config.Schemes = newConfig.Schemes
			return nil
		})

	_, err := config.Reload()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return config, nil
}

// LoadConfig loads, validates, and initializes a JSON encoded OSL
// configuration.
func LoadConfig(configJSON []byte) (*Config, error) {

	var config Config
	err := json.Unmarshal(configJSON, &config)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var previousEpoch time.Time

	for _, scheme := range config.Schemes {

		if scheme == nil {
			return nil, errors.TraceNew("invalid scheme")
		}

		epoch, err := time.Parse(time.RFC3339, scheme.Epoch)
		if err != nil {
			return nil, errors.Tracef("invalid epoch format: %s", err)
		}

		if epoch.UTC() != epoch {
			return nil, errors.TraceNew("invalid epoch timezone")
		}

		if epoch.Round(time.Duration(scheme.SeedPeriodNanoseconds)) != epoch {
			return nil, errors.TraceNew("invalid epoch period")
		}

		if epoch.Before(previousEpoch) {
			return nil, errors.TraceNew("invalid epoch order")
		}

		previousEpoch = epoch

		scheme.epoch = epoch
		scheme.subnetLookups = make([]common.SubnetLookup, len(scheme.SeedSpecs))
		scheme.derivedSLOKCache = make(map[slokReference]*SLOK)

		if len(scheme.MasterKey) != KEY_LENGTH_BYTES {
			return nil, errors.TraceNew("invalid master key")
		}

		for index, seedSpec := range scheme.SeedSpecs {

			if seedSpec == nil {
				return nil, errors.TraceNew("invalid seed spec")
			}

			if len(seedSpec.ID) != KEY_LENGTH_BYTES {
				return nil, errors.TraceNew("invalid seed spec ID")
			}

			// TODO: check that subnets do not overlap, as required by SubnetLookup
			subnetLookup, err := common.NewSubnetLookup(seedSpec.UpstreamSubnets)
			if err != nil {
				return nil, errors.Tracef("invalid upstream subnets: %s", err)
			}

			scheme.subnetLookups[index] = subnetLookup

			// Ensure there are no duplicates.
			ASNs := make(map[string]struct{}, len(seedSpec.UpstreamASNs))
			for _, ASN := range seedSpec.UpstreamASNs {
				if _, ok := ASNs[ASN]; ok {
					return nil, errors.Tracef("invalid upstream ASNs, duplicate ASN: %s", ASN)
				} else {
					ASNs[ASN] = struct{}{}
				}
			}
		}

		if !isValidShamirSplit(len(scheme.SeedSpecs), scheme.SeedSpecThreshold) {
			return nil, errors.TraceNew("invalid seed spec key split")
		}

		if len(scheme.SeedPeriodKeySplits) < 1 {
			return nil, errors.TraceNew("invalid seed period key split count")
		}

		for _, keySplit := range scheme.SeedPeriodKeySplits {
			if !isValidShamirSplit(keySplit.Total, keySplit.Threshold) {
				return nil, errors.TraceNew("invalid seed period key split")
			}
		}
	}

	return &config, nil
}

// NewClientSeedState creates a new client seed state to track
// client progress towards seeding SLOKs. psiphond maintains one
// ClientSeedState for each connected client.
//
// A signal is sent on signalIssueSLOKs when sufficient progress
// has been made that a new SLOK *may* be issued. psiphond will
// receive the signal and then call GetClientSeedPayload/IssueSLOKs
// to issue SLOKs, generate payload, and send to the client. The
// sender will not block sending to signalIssueSLOKs; the channel
// should be appropriately buffered.
func (config *Config) NewClientSeedState(
	clientRegion, propagationChannelID string,
	signalIssueSLOKs chan struct{}) *ClientSeedState {

	config.ReloadableFile.RLock()
	defer config.ReloadableFile.RUnlock()

	state := &ClientSeedState{
		propagationChannelID: propagationChannelID,
		signalIssueSLOKs:     signalIssueSLOKs,
		issuedSLOKs:          make(map[string]*SLOK),
		payloadSLOKs:         nil,
	}

	for _, scheme := range config.Schemes {

		// All matching schemes are selected.
		// Note: this implementation assumes a few simple schemes. For more
		// schemes with many propagation channel IDs or region filters, use
		// maps for more efficient lookup.
		if scheme.epoch.Before(time.Now().UTC()) &&
			common.Contains(scheme.PropagationChannelIDs, propagationChannelID) &&
			(len(scheme.Regions) == 0 || common.Contains(scheme.Regions, clientRegion)) {

			// Empty progress is initialized up front for all seed specs. Once
			// created, the progress structure is read-only (the slice, not the
			// TrafficValue fields); this permits lock-free operation.
			trafficProgress := make([]*TrafficValues, len(scheme.SeedSpecs))
			for index := 0; index < len(scheme.SeedSpecs); index++ {
				trafficProgress[index] = &TrafficValues{}
			}

			seedProgress := &ClientSeedProgress{
				scheme:           scheme,
				progressSLOKTime: getSLOKTime(scheme.SeedPeriodNanoseconds),
				trafficProgress:  trafficProgress,
			}

			state.seedProgress = append(state.seedProgress, seedProgress)
		}
	}

	return state
}

// Hibernate clears references to short-lived objects (currently,
// signalIssueSLOKs) so that a ClientSeedState can be stored for
// later resumption without blocking garbage collection of the
// short-lived objects.
//
// The ClientSeedState will still hold references to its Config;
// the caller is responsible for discarding hibernated seed states
// when the config changes.
//
// The caller should ensure that all ClientSeedPortForwards
// associated with this ClientSeedState are closed before
// hibernation.
func (state *ClientSeedState) Hibernate() {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	state.signalIssueSLOKs = nil
}

// Resume resumes a hibernated ClientSeedState by resetting the required
// objects (currently, signalIssueSLOKs) cleared by Hibernate.
func (state *ClientSeedState) Resume(
	signalIssueSLOKs chan struct{}) {

	state.mutex.Lock()
	defer state.mutex.Unlock()

	state.signalIssueSLOKs = signalIssueSLOKs
}

// NewClientSeedPortForward creates a new client port forward
// traffic progress tracker. Port forward progress reported to the
// ClientSeedPortForward is added to seed state progress for all
// seed specs containing upstreamIPAddress in their subnets or ASNs.
// The return value will be nil when activity for upstreamIPAddress
// does not count towards any progress.
// NewClientSeedPortForward may be invoked concurrently by many
// psiphond port forward establishment goroutines.
func (state *ClientSeedState) NewClientSeedPortForward(
	upstreamIPAddress net.IP,
	lookupASN func(net.IP) string) *ClientSeedPortForward {

	// Concurrency: access to ClientSeedState is unsynchronized
	// but references only read-only fields.

	if len(state.seedProgress) == 0 {
		return nil
	}

	var progressReferences []progressReference

	// Determine which seed spec subnets and ASNs contain upstreamIPAddress
	// and point to the progress for each. When progress is reported,
	// it is added directly to all of these TrafficValues instances.
	// Assumes state.seedProgress entries correspond 1-to-1 with
	// state.scheme.subnetLookups.
	// Note: this implementation assumes a small number of schemes and
	// seed specs. For larger numbers, instead of N SubnetLookups, create
	// a single SubnetLookup which returns, for a given IP address, all
	// matching subnets and associated seed specs.
	for seedProgressIndex, seedProgress := range state.seedProgress {

		var upstreamASN string
		var upstreamASNSet bool

		for trafficProgressIndex, seedSpec := range seedProgress.scheme.SeedSpecs {

			matchesSeedSpec := false

			// First check for subnet match before performing more expensive
			// check for ASN match.
			subnetLookup := seedProgress.scheme.subnetLookups[trafficProgressIndex]
			matchesSeedSpec = subnetLookup.ContainsIPAddress(upstreamIPAddress)

			if !matchesSeedSpec && lookupASN != nil {
				// No subnet match. Check for ASN match.
				if len(seedSpec.UpstreamASNs) > 0 {
					// Lookup ASN on demand and only once.
					if !upstreamASNSet {
						upstreamASN = lookupASN(upstreamIPAddress)
						upstreamASNSet = true
					}
					// TODO: use a map for faster lookups when the number of
					// string values to compare against exceeds a threshold
					// where benchmarks show maps are faster than looping
					// through a string slice.
					matchesSeedSpec = common.Contains(seedSpec.UpstreamASNs, upstreamASN)
				}
			}

			if matchesSeedSpec {
				progressReferences = append(
					progressReferences,
					progressReference{
						seedProgressIndex:    seedProgressIndex,
						trafficProgressIndex: trafficProgressIndex,
					})
			}
		}
	}

	if progressReferences == nil {
		return nil
	}

	return &ClientSeedPortForward{
		state:              state,
		progressReferences: progressReferences,
	}
}

func (state *ClientSeedState) sendIssueSLOKsSignal() {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.signalIssueSLOKs != nil {
		select {
		case state.signalIssueSLOKs <- struct{}{}:
		default:
		}
	}
}

// UpdateProgress adds port forward bytes transferred and duration to
// all seed spec progresses associated with the port forward.
// If UpdateProgress is invoked after the SLOK time period has rolled
// over, any pending seeded SLOKs are issued and all progress is reset.
// UpdateProgress may be invoked concurrently by many psiphond port
// relay goroutines. The implementation of UpdateProgress prioritizes
// not blocking port forward relaying; a consequence of this lock-free
// design is that progress reported at the exact time of SLOK time period
// rollover may be dropped.
func (portForward *ClientSeedPortForward) UpdateProgress(
	bytesRead, bytesWritten, durationNanoseconds int64) {

	// Concurrency: non-blocking -- access to ClientSeedState is unsynchronized
	// to read-only fields, atomic, or channels, except in the case of a time
	// period rollover, in which case a mutex is acquired.

	for _, progressReference := range portForward.progressReferences {

		seedProgress := portForward.state.seedProgress[progressReference.seedProgressIndex]
		trafficProgress := seedProgress.trafficProgress[progressReference.trafficProgressIndex]

		slokTime := getSLOKTime(seedProgress.scheme.SeedPeriodNanoseconds)

		// If the SLOK time period has changed since progress was last recorded,
		// call issueSLOKs which will issue any SLOKs for that past time period
		// and then clear all progress. Progress will then be recorded for the
		// current time period.
		// As it acquires the state mutex, issueSLOKs may stall other port
		// forwards for this client. The delay is minimized by SLOK caching,
		// which avoids redundant crypto operations.
		if slokTime != atomic.LoadInt64(&seedProgress.progressSLOKTime) {
			portForward.state.mutex.Lock()
			portForward.state.issueSLOKs()
			portForward.state.mutex.Unlock()

			// Call to issueSLOKs may have issued new SLOKs. Note that
			// this will only happen if the time period rolls over with
			// sufficient progress pending while the signalIssueSLOKs
			// receiver did not call IssueSLOKs soon enough.
			portForward.state.sendIssueSLOKsSignal()
		}

		// Add directly to the permanent TrafficValues progress accumulators
		// for the state's seed specs. Concurrently, other port forwards may
		// be adding to the same accumulators. Also concurrently, another
		// goroutine may be invoking issueSLOKs, which zeros all the accumulators.
		// As a consequence, progress may be dropped at the exact time of
		// time period rollover.

		seedSpec := seedProgress.scheme.SeedSpecs[progressReference.trafficProgressIndex]

		alreadyExceedsTargets := trafficProgress.exceeds(&seedSpec.Targets)

		atomic.AddInt64(&trafficProgress.BytesRead, bytesRead)
		atomic.AddInt64(&trafficProgress.BytesWritten, bytesWritten)
		atomic.AddInt64(&trafficProgress.PortForwardDurationNanoseconds, durationNanoseconds)

		// With the target newly met for a SeedSpec, a new
		// SLOK *may* be issued.
		if !alreadyExceedsTargets && trafficProgress.exceeds(&seedSpec.Targets) {
			portForward.state.sendIssueSLOKsSignal()
		}
	}
}

func (lhs *TrafficValues) exceeds(rhs *TrafficValues) bool {
	return atomic.LoadInt64(&lhs.BytesRead) >= atomic.LoadInt64(&rhs.BytesRead) &&
		atomic.LoadInt64(&lhs.BytesWritten) >= atomic.LoadInt64(&rhs.BytesWritten) &&
		atomic.LoadInt64(&lhs.PortForwardDurationNanoseconds) >=
			atomic.LoadInt64(&rhs.PortForwardDurationNanoseconds)
}

// issueSLOKs checks client progress against each candidate seed spec
// and seeds SLOKs when the client traffic levels are achieved. After
// checking progress, and if the SLOK time period has changed since
// progress was last recorded, progress is reset. Partial, insufficient
// progress is intentionally dropped when the time period rolls over.
// Derived SLOKs are cached to avoid redundant CPU intensive operations.
// All issued SLOKs are retained in the client state for the duration
// of the client's session.
func (state *ClientSeedState) issueSLOKs() {

	// Concurrency: the caller must lock state.mutex.

	if len(state.seedProgress) == 0 {
		return
	}

	for _, seedProgress := range state.seedProgress {

		progressSLOKTime := time.Unix(0, seedProgress.progressSLOKTime)

		for index, trafficProgress := range seedProgress.trafficProgress {

			seedSpec := seedProgress.scheme.SeedSpecs[index]

			if trafficProgress.exceeds(&seedSpec.Targets) {

				ref := &slokReference{
					PropagationChannelID: state.propagationChannelID,
					SeedSpecID:           string(seedSpec.ID),
					Time:                 progressSLOKTime,
				}

				seedProgress.scheme.derivedSLOKCacheMutex.RLock()
				slok, ok := seedProgress.scheme.derivedSLOKCache[*ref]
				seedProgress.scheme.derivedSLOKCacheMutex.RUnlock()
				if !ok {
					slok = seedProgress.scheme.deriveSLOK(ref)
					seedProgress.scheme.derivedSLOKCacheMutex.Lock()
					seedProgress.scheme.derivedSLOKCache[*ref] = slok
					seedProgress.scheme.derivedSLOKCacheMutex.Unlock()
				}

				// Previously issued SLOKs are not re-added to
				// the payload.
				if state.issuedSLOKs[string(slok.ID)] == nil {
					state.issuedSLOKs[string(slok.ID)] = slok
					state.payloadSLOKs = append(state.payloadSLOKs, slok)
				}
			}
		}

		slokTime := getSLOKTime(seedProgress.scheme.SeedPeriodNanoseconds)

		if slokTime != atomic.LoadInt64(&seedProgress.progressSLOKTime) {
			atomic.StoreInt64(&seedProgress.progressSLOKTime, slokTime)
			// The progress map structure is not reset or modifed; instead
			// the mapped accumulator values are zeroed. Concurrently, port
			// forward relay goroutines continue to add to these accumulators.
			for _, trafficProgress := range seedProgress.trafficProgress {
				atomic.StoreInt64(&trafficProgress.BytesRead, 0)
				atomic.StoreInt64(&trafficProgress.BytesWritten, 0)
				atomic.StoreInt64(&trafficProgress.PortForwardDurationNanoseconds, 0)
			}
		}
	}
}

func getSLOKTime(seedPeriodNanoseconds int64) int64 {
	return time.Now().UTC().Truncate(time.Duration(seedPeriodNanoseconds)).UnixNano()
}

// GetSeedPayload issues any pending SLOKs and returns the accumulated
// SLOKs for a given client. psiphond will calls this when it receives
// signalIssueSLOKs which is the trigger to check for new SLOKs.
// Note: caller must not modify the SLOKs in SeedPayload.SLOKs
// as these are shared data.
func (state *ClientSeedState) GetSeedPayload() *SeedPayload {

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if len(state.seedProgress) == 0 {
		return &SeedPayload{}
	}

	state.issueSLOKs()

	sloks := make([]*SLOK, len(state.payloadSLOKs))
	copy(sloks, state.payloadSLOKs)

	return &SeedPayload{
		SLOKs: sloks,
	}
}

// ClearSeedPayload resets the accumulated SLOK payload (but not SLOK
// progress). psiphond calls this after the client has acknowledged
// receipt of a payload.
func (state *ClientSeedState) ClearSeedPayload() {

	state.mutex.Lock()
	defer state.mutex.Unlock()

	state.payloadSLOKs = nil
}

// deriveSLOK produces SLOK secret keys and IDs using HKDF-Expand
// defined in https://tools.ietf.org/html/rfc5869.
func (scheme *Scheme) deriveSLOK(ref *slokReference) *SLOK {

	timeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timeBytes, uint64(ref.Time.UnixNano()))

	key := deriveKeyHKDF(
		scheme.MasterKey,
		[]byte(ref.PropagationChannelID),
		[]byte(ref.SeedSpecID),
		timeBytes)

	// TODO: is ID derivation cryptographically sound?
	id := deriveKeyHKDF(
		scheme.MasterKey,
		key)

	return &SLOK{
		ID:  id,
		Key: key,
	}
}

// GetOSLDuration returns the total time duration of an OSL,
// which is a function of the scheme's SeedPeriodNanoSeconds,
// the duration of a single SLOK, and the scheme's SeedPeriodKeySplits,
// the number of SLOKs associated with an OSL.
func (scheme *Scheme) GetOSLDuration() time.Duration {
	slokTimePeriodsPerOSL := 1
	for _, keySplit := range scheme.SeedPeriodKeySplits {
		slokTimePeriodsPerOSL *= keySplit.Total
	}

	return time.Duration(
		int64(slokTimePeriodsPerOSL) * scheme.SeedPeriodNanoseconds)
}

// PaveFile describes an OSL data file to be paved to an out-of-band
// distribution drop site. There are two types of files: a registry,
// which describes how to assemble keys for OSLs, and the encrypted
// OSL files.
type PaveFile struct {
	Name     string
	Contents []byte
}

// Registry describes a set of OSL files.
type Registry struct {
	FileSpecs []*OSLFileSpec
}

// An OSLFileSpec includes an ID which is used to reference the
// OSL file and describes the key splits used to divide the OSL
// file key along with the SLOKs required to reassemble those keys.
//
// The MD5Sum field is a checksum of the contents of the OSL file
// to be used to skip redownloading previously downloaded files.
// MD5 is not cryptographically secure and this checksum is not
// relied upon for OSL verification. MD5 is used for compatibility
// with out-of-band distribution hosts.
//
// OSLFileSpec supports compact CBOR encoding for use in alternative,
// fileless mechanisms.
type OSLFileSpec struct {
	ID        []byte     `cbor:"1,keyasint,omitempty"`
	KeyShares *KeyShares `cbor:"2,keyasint,omitempty"`
	MD5Sum    []byte     `cbor:"3,keyasint,omitempty"`
}

// KeyShares is a tree data structure which describes the
// key splits used to divide a secret key. BoxedShares are encrypted
// shares of the key, and #Threshold amount of decrypted BoxedShares
// are required to reconstruct the secret key. The keys for BoxedShares
// are either SLOKs (referenced by SLOK ID) or random keys that are
// themselves split as described in child KeyShares.
//
// KeyShares supports compact CBOR encoding for use in alternative,
// fileless mechanisms.
type KeyShares struct {
	Threshold   int          `cbor:"1,keyasint,omitempty"`
	BoxedShares [][]byte     `cbor:"2,keyasint,omitempty"`
	SLOKIDs     [][]byte     `cbor:"3,keyasint,omitempty"`
	KeyShares   []*KeyShares `cbor:"4,keyasint,omitempty"`
}

type PaveLogInfo struct {
	FileName             string
	SchemeIndex          int
	PropagationChannelID string
	OSLID                string
	OSLTime              time.Time
	OSLDuration          time.Duration
	ServerEntryCount     int
}

// Pave creates the full set of OSL files, for all schemes in the
// configuration, to be dropped in an out-of-band distribution site.
// Only OSLs for the propagation channel ID associated with the
// distribution site are paved. This function is used by automation.
//
// The Name component of each file relates to the values returned by
// the client functions GetRegistryURL and GetOSLFileURL.
//
// Pave returns a pave file for the entire registry of all OSLs from
// epoch to endTime, and a pave file for each OSL. paveServerEntries is
// a map from hex-encoded OSL IDs to server entries to pave into that OSL.
// When entries are found, OSL will contain those entries, newline
// separated. Otherwise the OSL will still be issued, but be empty (unless
// the scheme is in omitEmptyOSLsSchemes). The server entries are paved
// in string value sort order, ensuring that the OSL content remains
// constant as long as the same _set_ of server entries is input.
//
// If startTime is specified and is after epoch, the pave file will contain
// OSLs for the first period at or after startTime.
//
// As OSLs outside the epoch-endTime range will no longer appear in
// the registry, Pave is intended to be used to create the full set
// of OSLs for a distribution site; i.e., not incrementally.
//
// Automation is responsible for consistently distributing server entries
// to OSLs in the case where OSLs are repaved in subsequent calls.
func (config *Config) Pave(
	startTime time.Time,
	endTime time.Time,
	propagationChannelID string,
	signingPublicKey string,
	signingPrivateKey string,
	paveServerEntries map[string][]string,
	omitMD5SumsSchemes []int,
	omitEmptyOSLsSchemes []int,
	logCallback func(*PaveLogInfo)) ([]*PaveFile, error) {

	config.ReloadableFile.RLock()
	defer config.ReloadableFile.RUnlock()

	var paveFiles []*PaveFile

	registry := &Registry{}

	for schemeIndex, scheme := range config.Schemes {
		if common.Contains(scheme.PropagationChannelIDs, propagationChannelID) {

			omitMD5Sums := common.ContainsInt(omitMD5SumsSchemes, schemeIndex)

			omitEmptyOSLs := common.ContainsInt(omitEmptyOSLsSchemes, schemeIndex)

			oslDuration := scheme.GetOSLDuration()

			oslTime := scheme.epoch

			if !startTime.IsZero() && !startTime.Before(scheme.epoch) {
				for oslTime.Before(startTime) {
					oslTime = oslTime.Add(oslDuration)
				}
			}

			for !oslTime.After(endTime) {

				firstSLOKTime := oslTime
				fileKey, fileSpec, err := makeOSLFileSpec(
					scheme, propagationChannelID, firstSLOKTime)
				if err != nil {
					return nil, errors.Trace(err)
				}

				hexEncodedOSLID := hex.EncodeToString(fileSpec.ID)

				serverEntryCount := len(paveServerEntries[hexEncodedOSLID])

				if serverEntryCount > 0 || !omitEmptyOSLs {

					registry.FileSpecs = append(registry.FileSpecs, fileSpec)

					serverEntries := append([]string(nil), paveServerEntries[hexEncodedOSLID]...)
					sort.Strings(serverEntries)

					// payload will be "" when nothing is found in serverEntries
					payload := strings.Join(serverEntries, "\n")

					serverEntriesPackage, err := common.WriteAuthenticatedDataPackage(
						payload,
						signingPublicKey,
						signingPrivateKey)
					if err != nil {
						return nil, errors.Trace(err)
					}

					boxedServerEntries, err := box(fileKey, serverEntriesPackage)
					if err != nil {
						return nil, errors.Trace(err)
					}

					if !omitMD5Sums {
						md5sum := md5.Sum(boxedServerEntries)
						fileSpec.MD5Sum = md5sum[:]
					}

					fileName := fmt.Sprintf(
						OSL_FILENAME_FORMAT, hexEncodedOSLID)

					paveFiles = append(paveFiles, &PaveFile{
						Name:     fileName,
						Contents: boxedServerEntries,
					})

					if logCallback != nil {
						logCallback(&PaveLogInfo{
							FileName:             fileName,
							SchemeIndex:          schemeIndex,
							PropagationChannelID: propagationChannelID,
							OSLID:                hexEncodedOSLID,
							OSLTime:              oslTime,
							OSLDuration:          oslDuration,
							ServerEntryCount:     serverEntryCount,
						})
					}
				}

				oslTime = oslTime.Add(oslDuration)
			}
		}
	}

	registryJSON, err := json.Marshal(registry)
	if err != nil {
		return nil, errors.Trace(err)
	}

	registryPackage, err := common.WriteAuthenticatedDataPackage(
		base64.StdEncoding.EncodeToString(registryJSON),
		signingPublicKey,
		signingPrivateKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	paveFiles = append(paveFiles, &PaveFile{
		Name:     REGISTRY_FILENAME,
		Contents: registryPackage,
	})

	return paveFiles, nil
}

// CurrentOSLIDs returns a mapping from each propagation channel ID in the
// specified scheme to the corresponding current time period, hex-encoded OSL ID.
func (config *Config) CurrentOSLIDs(schemeIndex int) (map[string]string, error) {

	config.ReloadableFile.RLock()
	defer config.ReloadableFile.RUnlock()

	if schemeIndex < 0 || schemeIndex >= len(config.Schemes) {
		return nil, errors.TraceNew("invalid scheme index")
	}

	scheme := config.Schemes[schemeIndex]
	now := time.Now().UTC()
	oslDuration := scheme.GetOSLDuration()
	oslTime := scheme.epoch.Add((now.Sub(scheme.epoch) / oslDuration) * oslDuration)

	OSLIDs := make(map[string]string)
	for _, propagationChannelID := range scheme.PropagationChannelIDs {
		_, fileSpec, err := makeOSLFileSpec(scheme, propagationChannelID, oslTime)
		if err != nil {
			return nil, errors.Trace(err)
		}
		OSLIDs[propagationChannelID] = hex.EncodeToString(fileSpec.ID)
	}

	return OSLIDs, nil
}

// PaveData is the per-OSL data used by Pave, for use in alternative, fileless
// mechanisms, such as proof-of-knowledge of keys. PaveData.FileSpec is the
// OSL FileSpec that would be paved into the registry file, and
// PaveData.FileKey is the key that would be used to encrypt OSL files.
type PaveData struct {
	FileSpec *OSLFileSpec
	FileKey  []byte
}

// GetPaveData returns, for each propagation channel ID in the specified
// scheme, the list of OSL PaveData for the Config.PaveDataOSLCount most
// recent OSLs from now. GetPaveData is the equivilent of Pave that is for
// use in alternative, fileless mechanisms, such as proof-of-knowledge of
// keys
func (config *Config) GetPaveData(schemeIndex int) (map[string][]*PaveData, error) {

	config.ReloadableFile.RLock()
	defer config.ReloadableFile.RUnlock()

	if schemeIndex < 0 || schemeIndex >= len(config.Schemes) {
		return nil, errors.TraceNew("invalid scheme index")
	}

	scheme := config.Schemes[schemeIndex]

	oslDuration := scheme.GetOSLDuration()

	// Using PaveDataOSLCount, initialize startTime and EndTime values that
	// are similar to the Pave inputs. As in Pave, logic in the following
	// loop will align these time values to actual OSL periods.

	if scheme.PaveDataOSLCount < 1 {
		return nil, errors.TraceNew("invalid OSL count")
	}
	endTime := time.Now()
	startTime := endTime.Add(-time.Duration(scheme.PaveDataOSLCount) * oslDuration)
	if startTime.Before(scheme.epoch) {
		startTime = scheme.epoch
	}

	allPaveData := make(map[string][]*PaveData)

	for _, propagationChannelID := range scheme.PropagationChannelIDs {

		if !common.Contains(scheme.PropagationChannelIDs, propagationChannelID) {
			return nil, errors.TraceNew("invalid propagationChannelID")
		}

		var paveData []*PaveData

		oslTime := scheme.epoch

		if !startTime.IsZero() && !startTime.Before(scheme.epoch) {
			for oslTime.Before(startTime) {
				oslTime = oslTime.Add(oslDuration)
			}
		}

		for !oslTime.After(endTime) {

			firstSLOKTime := oslTime
			fileKey, fileSpec, err := makeOSLFileSpec(
				scheme, propagationChannelID, firstSLOKTime)
			if err != nil {
				return nil, errors.Trace(err)
			}

			paveData = append(paveData, &PaveData{FileSpec: fileSpec, FileKey: fileKey})

			oslTime = oslTime.Add(oslDuration)
		}

		allPaveData[propagationChannelID] = paveData
	}

	return allPaveData, nil
}

// makeOSLFileSpec creates an OSL file key, splits it according to the
// scheme's key splits, and sets the OSL ID as its first SLOK ID. The
// returned key is used to encrypt the OSL payload and then discarded;
// the key may be reassembled using the data in the KeyShares tree,
// given sufficient SLOKs.
func makeOSLFileSpec(
	scheme *Scheme,
	propagationChannelID string,
	firstSLOKTime time.Time) ([]byte, *OSLFileSpec, error) {

	ref := &slokReference{
		PropagationChannelID: propagationChannelID,
		SeedSpecID:           string(scheme.SeedSpecs[0].ID),
		Time:                 firstSLOKTime,
	}
	firstSLOK := scheme.deriveSLOK(ref)
	oslID := firstSLOK.ID

	// Note: previously, fileKey was a random key. Now, the key
	// is derived from the master key and OSL ID. This deterministic
	// derivation ensures that repeated paves of the same OSL
	// with the same ID and same content yields the same MD5Sum
	// to avoid wasteful downloads.
	//
	// Similarly, the shareKeys generated in divideKey and the Shamir
	// key splitting random polynomials are now both determinisitcally
	// generated from a seeded CSPRNG. This ensures that the OSL
	// registry remains identical for repeated paves of the same config
	// and parameters.
	//
	// The split structure is added to the deterministic key
	// derivation so that changes to the split configuration will not
	// expose the same key material to different SLOK combinations.

	splitStructure := make([]byte, 16*(1+len(scheme.SeedPeriodKeySplits)))
	i := 0
	binary.LittleEndian.PutUint64(splitStructure[i:], uint64(len(scheme.SeedSpecs)))
	binary.LittleEndian.PutUint64(splitStructure[i+8:], uint64(scheme.SeedSpecThreshold))
	i += 16
	for _, keySplit := range scheme.SeedPeriodKeySplits {
		binary.LittleEndian.PutUint64(splitStructure[i:], uint64(keySplit.Total))
		binary.LittleEndian.PutUint64(splitStructure[i+8:], uint64(keySplit.Threshold))
		i += 16
	}

	fileKey := deriveKeyHKDF(
		scheme.MasterKey,
		splitStructure,
		[]byte("osl-file-key"),
		oslID)

	splitKeyMaterialSeed := deriveKeyHKDF(
		scheme.MasterKey,
		splitStructure,
		[]byte("osl-file-split-key-material-seed"),
		oslID)

	keyMaterialReader, err := newSeededKeyMaterialReader(splitKeyMaterialSeed)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	keyShares, err := divideKey(
		scheme,
		keyMaterialReader,
		fileKey,
		scheme.SeedPeriodKeySplits,
		propagationChannelID,
		&firstSLOKTime)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	fileSpec := &OSLFileSpec{
		ID:        oslID,
		KeyShares: keyShares,
	}

	return fileKey, fileSpec, nil
}

// divideKey recursively constructs a KeyShares tree.
func divideKey(
	scheme *Scheme,
	keyMaterialReader io.Reader,
	key []byte,
	keySplits []KeySplit,
	propagationChannelID string,
	nextSLOKTime *time.Time) (*KeyShares, error) {

	keySplitIndex := len(keySplits) - 1
	keySplit := keySplits[keySplitIndex]

	shares, err := shamirSplit(
		key,
		keySplit.Total,
		keySplit.Threshold,
		keyMaterialReader)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var boxedShares [][]byte
	var keyShares []*KeyShares

	for _, share := range shares {

		var shareKey [KEY_LENGTH_BYTES]byte

		n, err := keyMaterialReader.Read(shareKey[:])
		if err == nil && n != len(shareKey) {
			err = std_errors.New("unexpected length")
		}
		if err != nil {
			return nil, errors.Trace(err)
		}

		if keySplitIndex > 0 {
			keyShare, err := divideKey(
				scheme,
				keyMaterialReader,
				shareKey[:],
				keySplits[0:keySplitIndex],
				propagationChannelID,
				nextSLOKTime)
			if err != nil {
				return nil, errors.Trace(err)
			}
			keyShares = append(keyShares, keyShare)
		} else {
			keyShare, err := divideKeyWithSeedSpecSLOKs(
				scheme,
				keyMaterialReader,
				shareKey[:],
				propagationChannelID,
				nextSLOKTime)
			if err != nil {
				return nil, errors.Trace(err)
			}
			keyShares = append(keyShares, keyShare)

			*nextSLOKTime = nextSLOKTime.Add(time.Duration(scheme.SeedPeriodNanoseconds))
		}
		boxedShare, err := box(shareKey[:], share)
		if err != nil {
			return nil, errors.Trace(err)
		}
		boxedShares = append(boxedShares, boxedShare)
	}

	return &KeyShares{
		Threshold:   keySplit.Threshold,
		BoxedShares: boxedShares,
		SLOKIDs:     nil,
		KeyShares:   keyShares,
	}, nil
}

func divideKeyWithSeedSpecSLOKs(
	scheme *Scheme,
	keyMaterialReader io.Reader,
	key []byte,
	propagationChannelID string,
	nextSLOKTime *time.Time) (*KeyShares, error) {

	var boxedShares [][]byte
	var slokIDs [][]byte

	shares, err := shamirSplit(
		key,
		len(scheme.SeedSpecs),
		scheme.SeedSpecThreshold,
		keyMaterialReader)
	if err != nil {
		return nil, errors.Trace(err)
	}

	for index, seedSpec := range scheme.SeedSpecs {

		ref := &slokReference{
			PropagationChannelID: propagationChannelID,
			SeedSpecID:           string(seedSpec.ID),
			Time:                 *nextSLOKTime,
		}
		slok := scheme.deriveSLOK(ref)

		boxedShare, err := box(slok.Key, shares[index])
		if err != nil {
			return nil, errors.Trace(err)
		}
		boxedShares = append(boxedShares, boxedShare)

		slokIDs = append(slokIDs, slok.ID)
	}

	return &KeyShares{
		Threshold:   scheme.SeedSpecThreshold,
		BoxedShares: boxedShares,
		SLOKIDs:     slokIDs,
		KeyShares:   nil,
	}, nil
}

// reassembleKey recursively traverses a KeyShares tree, determining
// whether there exists suffient SLOKs to reassemble the root key and
// performing the key assembly as required.
func (keyShares *KeyShares) reassembleKey(lookup SLOKLookup, unboxKey bool) (bool, []byte, error) {

	if (len(keyShares.SLOKIDs) > 0 && len(keyShares.KeyShares) > 0) ||
		(len(keyShares.SLOKIDs) > 0 && len(keyShares.SLOKIDs) != len(keyShares.BoxedShares)) ||
		(len(keyShares.KeyShares) > 0 && len(keyShares.KeyShares) != len(keyShares.BoxedShares)) {
		return false, nil, errors.TraceNew("unexpected KeyShares format")
	}

	shareCount := 0
	var shares [][]byte
	if unboxKey {
		// Note: shamirCombine infers share indices from slice offset, so the full
		// keyShares.Total slots are allocated and missing shares are left nil.
		shares = make([][]byte, len(keyShares.BoxedShares))
	}
	if len(keyShares.SLOKIDs) > 0 {
		for i := 0; i < len(keyShares.SLOKIDs) && shareCount < keyShares.Threshold; i++ {
			slokKey := lookup(keyShares.SLOKIDs[i])
			if slokKey == nil {
				continue
			}
			shareCount += 1
			if unboxKey {
				share, err := unbox(slokKey, keyShares.BoxedShares[i])
				if err != nil {
					return false, nil, errors.Trace(err)
				}
				shares[i] = share
			}
		}
	} else {
		for i := 0; i < len(keyShares.KeyShares) && shareCount < keyShares.Threshold; i++ {
			ok, key, err := keyShares.KeyShares[i].reassembleKey(lookup, unboxKey)
			if err != nil {
				return false, nil, errors.Trace(err)
			}
			if !ok {
				continue
			}
			shareCount += 1
			if unboxKey {
				share, err := unbox(key, keyShares.BoxedShares[i])
				if err != nil {
					return false, nil, errors.Trace(err)
				}
				shares[i] = share
			}
		}
	}

	if shareCount < keyShares.Threshold {
		return false, nil, nil
	}

	if !unboxKey {
		return true, nil, nil
	}

	joinedKey := shamirCombine(shares)

	return true, joinedKey, nil
}

// GetOSLRegistryURL returns the URL for an OSL registry. Clients
// call this when fetching the registry from out-of-band
// distribution sites.
// Clients are responsible for tracking whether the remote file has
// changed or not before downloading.
func GetOSLRegistryURL(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	u.Path = path.Join(u.Path, REGISTRY_FILENAME)
	return u.String()
}

// GetOSLRegistryFilename returns an appropriate filename for
// the resumable download destination for the OSL registry.
func GetOSLRegistryFilename(baseDirectory string) string {
	return filepath.Join(baseDirectory, REGISTRY_FILENAME)
}

// GetOSLFileURL returns the URL for an OSL file. Once the client
// has determined, from GetSeededOSLIDs, which OSLs it has sufficiently
// seeded, it calls this to fetch the OSLs for download and decryption.
// Clients are responsible for tracking whether the remote file has
// changed or not before downloading.
func GetOSLFileURL(baseURL string, oslID []byte) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	u.Path = path.Join(
		u.Path, fmt.Sprintf(OSL_FILENAME_FORMAT, hex.EncodeToString(oslID)))
	return u.String()
}

// GetOSLFilename returns an appropriate filename for the resumable
// download destination for the OSL file.
func GetOSLFilename(baseDirectory string, oslID []byte) string {
	return filepath.Join(
		baseDirectory, fmt.Sprintf(OSL_FILENAME_FORMAT, hex.EncodeToString(oslID)))
}

// SLOKLookup is a callback to lookup SLOK keys by ID.
type SLOKLookup func([]byte) []byte

// RegistryStreamer authenticates and processes a JSON encoded OSL registry.
// The streamer processes the registry without loading the entire file
// into memory, parsing each OSL file spec in turn and returning those
// OSL file specs for which the client has sufficient SLOKs to reassemble
// the OSL key and decrypt.
//
// At this stage, SLOK reassembly simply does SLOK ID lookups and threshold
// counting and does not derive keys for every OSL. This allows the client
// to defer key derivation until NewOSLReader for cases where it has not
// already imported the OSL.
//
// The client's propagation channel ID is used implicitly: it determines the
// base URL used to download the registry and OSL files. If the client has
// seeded SLOKs from a propagation channel ID different than the one associated
// with its present base URL, they will not appear in the registry and not
// be used.
type RegistryStreamer struct {
	jsonDecoder *json.Decoder
	lookup      SLOKLookup
}

// NewRegistryStreamer creates a new RegistryStreamer.
func NewRegistryStreamer(
	registryFileContent io.ReadSeeker,
	signingPublicKey string,
	lookup SLOKLookup) (*RegistryStreamer, error) {

	payloadReader, err := common.NewAuthenticatedDataPackageReader(
		registryFileContent, signingPublicKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	base64Decoder := base64.NewDecoder(base64.StdEncoding, payloadReader)

	// A json.Decoder is used to stream the JSON payload, which
	// is expected to be of the following form, corresponding
	// to the Registry struct type:
	//
	// {"FileSpecs" : [{...}, {...}, ..., {...}]}

	jsonDecoder := json.NewDecoder(base64Decoder)

	err = expectJSONDelimiter(jsonDecoder, "{")
	if err != nil {
		return nil, errors.Trace(err)
	}

	token, err := jsonDecoder.Token()
	if err != nil {
		return nil, errors.Trace(err)
	}

	name, ok := token.(string)

	if !ok {
		return nil, errors.Trace(
			fmt.Errorf("unexpected token type: %T", token))
	}

	if name != "FileSpecs" {
		return nil, errors.Trace(
			fmt.Errorf("unexpected field name: %s", name))
	}

	err = expectJSONDelimiter(jsonDecoder, "[")
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &RegistryStreamer{
		jsonDecoder: jsonDecoder,
		lookup:      lookup,
	}, nil
}

// Next returns the next OSL file spec that the client
// has sufficient SLOKs to decrypt. The client calls
// NewOSLReader with the file spec to process that OSL.
// Next returns nil at EOF.
func (s *RegistryStreamer) Next() (*OSLFileSpec, error) {

	for {
		if s.jsonDecoder.More() {

			var fileSpec OSLFileSpec
			err := s.jsonDecoder.Decode(&fileSpec)
			if err != nil {
				return nil, errors.Trace(err)
			}

			ok, _, err := fileSpec.KeyShares.reassembleKey(s.lookup, false)
			if err != nil {
				return nil, errors.Trace(err)
			}

			if ok {
				return &fileSpec, nil
			}

		} else {

			// Expect the end of the FileSpecs array.
			err := expectJSONDelimiter(s.jsonDecoder, "]")
			if err != nil {
				return nil, errors.Trace(err)
			}

			// Expect the end of the Registry object.
			err = expectJSONDelimiter(s.jsonDecoder, "}")
			if err != nil {
				return nil, errors.Trace(err)
			}

			// Expect the end of the registry content.
			_, err = s.jsonDecoder.Token()
			if err != io.EOF {
				return nil, errors.Trace(err)
			}

			return nil, nil
		}
	}
}

func expectJSONDelimiter(jsonDecoder *json.Decoder, delimiter string) error {
	token, err := jsonDecoder.Token()
	if err != nil {
		return errors.Trace(err)
	}

	delim, ok := token.(json.Delim)

	if !ok {
		return errors.Tracef("unexpected token type: %T", token)
	}

	if delim.String() != delimiter {
		return errors.Tracef("unexpected delimiter: %s", delim.String())
	}

	return nil
}

// NewOSLReader decrypts, authenticates and streams an OSL payload.
func NewOSLReader(
	oslFileContent io.ReadSeeker,
	fileSpec *OSLFileSpec,
	lookup SLOKLookup,
	signingPublicKey string) (io.Reader, error) {

	ok, fileKey, err := fileSpec.KeyShares.reassembleKey(lookup, true)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if !ok {
		return nil, errors.TraceNew("unseeded OSL")
	}

	if len(fileKey) != KEY_LENGTH_BYTES {
		return nil, errors.TraceNew("invalid key length")
	}

	var nonce [24]byte
	var key [KEY_LENGTH_BYTES]byte
	copy(key[:], fileKey)

	unboxer, err := secretbox.NewOpenReadSeeker(oslFileContent, &nonce, &key)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return common.NewAuthenticatedDataPackageReader(
		unboxer,
		signingPublicKey)
}

// ReassembleOSLKey returns a reassembled OSL key, for use in alternative,
// fileless mechanisms, such as proof-of-knowledge of keys.
func ReassembleOSLKey(
	fileSpec *OSLFileSpec,
	lookup SLOKLookup) (bool, []byte, error) {

	ok, fileKey, err := fileSpec.KeyShares.reassembleKey(lookup, true)
	if err != nil {
		return false, nil, errors.Trace(err)
	}
	if !ok {
		return false, nil, nil
	}
	if len(fileKey) != KEY_LENGTH_BYTES {
		return false, nil, errors.TraceNew("invalid key length")
	}

	return true, fileKey, nil
}

// zeroReader reads an unlimited stream of zeroes.
type zeroReader struct {
}

func (z *zeroReader) Read(p []byte) (int, error) {
	for i := 0; i < len(p); i++ {
		p[i] = 0
	}
	return len(p), nil
}

// newSeededKeyMaterialReader constructs a CSPRNG using AES-CTR.
// The seed is the AES key and the IV is fixed and constant.
// Using same seed will always produce the same output stream.
// The data stream is intended to be used to deterministically
// generate key material and is not intended as a general
// purpose CSPRNG.
func newSeededKeyMaterialReader(seed []byte) (io.Reader, error) {

	if len(seed) != KEY_LENGTH_BYTES {
		return nil, errors.TraceNew("invalid key length")
	}

	aesCipher, err := aes.NewCipher(seed)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var iv [aes.BlockSize]byte

	return &cipher.StreamReader{
		S: cipher.NewCTR(aesCipher, iv[:]),
		R: new(zeroReader),
	}, nil
}

// deriveKeyHKDF implements HKDF-Expand as defined in https://tools.ietf.org/html/rfc5869
// where masterKey = PRK, context = info, and L = 32; SHA-256 is used so HashLen = 32
func deriveKeyHKDF(masterKey []byte, context ...[]byte) []byte {

	// TODO: use golang.org/x/crypto/hkdf?

	mac := hmac.New(sha256.New, masterKey)
	for _, item := range context {
		mac.Write([]byte(item))
	}
	mac.Write([]byte{byte(0x01)})
	return mac.Sum(nil)
}

// isValidShamirSplit checks sss.Split constraints
func isValidShamirSplit(total, threshold int) bool {
	if total < 1 || total > 254 || threshold < 1 || threshold > total {
		return false
	}
	return true
}

// shamirSplit is a helper wrapper for sss.Split
func shamirSplit(
	secret []byte,
	total, threshold int,
	randReader io.Reader) ([][]byte, error) {

	if !isValidShamirSplit(total, threshold) {
		return nil, errors.TraceNew("invalid parameters")
	}

	if threshold == 1 {
		// Special case: each share is simply the secret
		shares := make([][]byte, total)
		for i := 0; i < total; i++ {
			shares[i] = secret
		}
		return shares, nil
	}

	shareMap, err := sss.SplitUsingReader(
		byte(total), byte(threshold), secret, randReader)
	if err != nil {
		return nil, errors.Trace(err)
	}

	shares := make([][]byte, total)
	for i := 0; i < total; i++ {
		// Note: sss.Combine index starts at 1
		shares[i] = shareMap[byte(i)+1]
	}

	return shares, nil
}

// shamirCombine is a helper wrapper for sss.Combine
func shamirCombine(shares [][]byte) []byte {

	if len(shares) == 1 {
		// Special case: each share is simply the secret
		return shares[0]
	}

	// Convert a sparse list into a map
	shareMap := make(map[byte][]byte)
	for index, share := range shares {
		if share != nil {
			// Note: sss.Combine index starts at 1
			shareMap[byte(index)+1] = share
		}
	}

	return sss.Combine(shareMap)
}

// box is a helper wrapper for secretbox.Seal.
// A constant nonce is used, which is secure so long as
// each key is used to encrypt only one message.
func box(key, plaintext []byte) ([]byte, error) {
	if len(key) != KEY_LENGTH_BYTES {
		return nil, errors.TraceNew("invalid key length")
	}
	var nonce [24]byte
	var secretboxKey [KEY_LENGTH_BYTES]byte
	copy(secretboxKey[:], key)
	box := secretbox.Seal(nil, plaintext, &nonce, &secretboxKey)
	return box, nil
}

// unbox is a helper wrapper for secretbox.Open
func unbox(key, box []byte) ([]byte, error) {
	if len(key) != KEY_LENGTH_BYTES {
		return nil, errors.TraceNew("invalid key length")
	}
	var nonce [24]byte
	var secretboxKey [KEY_LENGTH_BYTES]byte
	copy(secretboxKey[:], key)
	plaintext, ok := secretbox.Open(nil, box, &nonce, &secretboxKey)
	if !ok {
		return nil, errors.TraceNew("unbox failed")
	}
	return plaintext, nil
}
