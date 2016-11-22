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
// keys are stored and later comboined to assemble keys to decrypt out-of-band
// distributed OSL files that contain server lists.
//
// This package contains the core routines used in psiphond (to track client
// traits and issue SLOKs), clients (to manage SLOKs and decrypt OSLs), and
// automation (to create OSLs for distribution).
package osl

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"path"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Inc/crypto/nacl/secretbox"
	"github.com/Psiphon-Inc/sss"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
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

	// Regions is a list of client country codes this scheme applies to.
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
	// SLOK is issued for each SeedLevel in each SeedSpec.
	// Duplicate subnets may appear in multiple SeedSpecs.
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
	// Limitation: thresholds must be at least 2.
	//
	// Example:
	//
	//   SeedSpecs = <3 specs>
	//   SeedSpecThreshold = 2
	//   SeedPeriodNanoseconds = 100,000,000 = 100 milliseconds
	//   SeedPeriodKeySplits = [{10, 7}, {60, 5}]
	//
	//   In these scheme, up to 3 distinct SLOKs, one per spec, are issued
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
// UpstreamSubnets is counted towards the targets.
//
// ID is a SLOK key derivation component and must be 32 random bytes, base64
// encoded. UpstreamSubnets is a list of CIDRs. Description is not used; it's
// for JSON config file comments.
type SeedSpec struct {
	Description     string
	ID              []byte
	UpstreamSubnets []string
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

// ClientSeedState tracks the progress of a client towards seeding SLOKs.
type ClientSeedState struct {
	scheme               *Scheme
	propagationChannelID string
	signalIssueSLOKs     chan struct{}
	progress             []*TrafficValues
	progressSLOKTime     int64
	mutex                sync.Mutex
	issuedSLOKs          map[string]*SLOK
	payloadSLOKs         []*SLOK
}

// ClientSeedPortForward map a client port forward, which is relaying
// traffic to a specific upstream address, to all seed state progress
// counters for SeedSpecs with subnets containing the upstream address.
// As traffic is relayed through the port forwards, the bytes transferred
// and duration count towards the progress of these SeedSpecs and
// associated SLOKs.
type ClientSeedPortForward struct {
	state           *ClientSeedState
	progressIndexes []int
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
		func(fileContent []byte) error {
			newConfig, err := LoadConfig(fileContent)
			if err != nil {
				return common.ContextError(err)
			}
			// Modify actual traffic rules only after validation
			config.Schemes = newConfig.Schemes
			return nil
		})

	_, err := config.Reload()
	if err != nil {
		return nil, common.ContextError(err)
	}

	return config, nil
}

// LoadConfig loads, vaildates, and initializes a JSON encoded OSL
// configuration.
func LoadConfig(configJSON []byte) (*Config, error) {

	var config Config
	err := json.Unmarshal(configJSON, &config)
	if err != nil {
		return nil, common.ContextError(err)
	}

	var previousEpoch time.Time

	for _, scheme := range config.Schemes {

		epoch, err := time.Parse(time.RFC3339, scheme.Epoch)
		if err != nil {
			return nil, common.ContextError(fmt.Errorf("invalid epoch format: %s", err))
		}

		if epoch.UTC() != epoch {
			return nil, common.ContextError(errors.New("invalid epoch timezone"))
		}

		if epoch.Round(time.Duration(scheme.SeedPeriodNanoseconds)) != epoch {
			return nil, common.ContextError(errors.New("invalid epoch period"))
		}

		if epoch.Before(previousEpoch) {
			return nil, common.ContextError(errors.New("invalid epoch order"))
		}

		previousEpoch = epoch

		scheme.epoch = epoch
		scheme.subnetLookups = make([]common.SubnetLookup, len(scheme.SeedSpecs))
		scheme.derivedSLOKCache = make(map[slokReference]*SLOK)

		if len(scheme.MasterKey) != KEY_LENGTH_BYTES {
			return nil, common.ContextError(errors.New("invalid master key"))
		}

		for index, seedSpec := range scheme.SeedSpecs {
			if len(seedSpec.ID) != KEY_LENGTH_BYTES {
				return nil, common.ContextError(errors.New("invalid seed spec ID"))
			}

			// TODO: check that subnets do not overlap, as required by SubnetLookup
			subnetLookup, err := common.NewSubnetLookup(seedSpec.UpstreamSubnets)
			if err != nil {
				return nil, common.ContextError(fmt.Errorf("invalid upstream subnets: %s", err))
			}

			scheme.subnetLookups[index] = subnetLookup
		}

		if !isValidShamirSplit(len(scheme.SeedSpecs), scheme.SeedSpecThreshold) {
			return nil, common.ContextError(errors.New("invalid seed spec key split"))
		}

		if len(scheme.SeedPeriodKeySplits) < 1 {
			return nil, common.ContextError(errors.New("invalid seed period key split count"))
		}

		for _, keySplit := range scheme.SeedPeriodKeySplits {
			if !isValidShamirSplit(keySplit.Total, keySplit.Threshold) {
				return nil, common.ContextError(errors.New("invalid seed period key split"))
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

	for _, scheme := range config.Schemes {
		// Only the first matching scheme is selected.
		// Note: this implementation assumes a few simple schemes. For more
		// schemes with many propagation channel IDs or region filters, use
		// maps for more efficient lookup.
		if scheme.epoch.Before(time.Now().UTC()) &&
			common.Contains(scheme.PropagationChannelIDs, propagationChannelID) &&
			(len(scheme.Regions) == 0 || common.Contains(scheme.Regions, clientRegion)) {

			// Empty progress is initialized up front for all seed specs. Once
			// created, the progress structure is read-only (the slice, not the
			// TrafficValue fields); this permits lock-free operation.
			progress := make([]*TrafficValues, len(scheme.SeedSpecs))
			for index := 0; index < len(scheme.SeedSpecs); index++ {
				progress[index] = &TrafficValues{}
			}

			return &ClientSeedState{
				scheme:               scheme,
				propagationChannelID: propagationChannelID,
				signalIssueSLOKs:     signalIssueSLOKs,
				progressSLOKTime:     getSLOKTime(scheme.SeedPeriodNanoseconds),
				progress:             progress,
				issuedSLOKs:          make(map[string]*SLOK),
				payloadSLOKs:         nil,
			}
		}
	}

	return &ClientSeedState{}
}

// NewClientSeedPortForwardState creates a new client port forward
// traffic progress tracker. Port forward progress reported to the
// ClientSeedPortForward is added to seed state progress for all
// seed specs containing upstreamIPAddress in their subnets.
// The return value will be nil when activity for upstreamIPAddress
// does not count towards any progress.
// NewClientSeedPortForward may be invoked concurrently by many
// psiphond port forward establishment goroutines.
func (state *ClientSeedState) NewClientSeedPortForward(
	upstreamIPAddress net.IP) *ClientSeedPortForward {

	// Concurrency: access to ClientSeedState is unsynchronized
	// but references only read-only fields.

	if state.scheme == nil {
		return nil
	}

	var progressIndexes []int

	// Determine which seed spec subnets contain upstreamIPAddress
	// and point to the progress for each. When progress is reported,
	// it is added directly to all of these TrafficValues instances.
	// Assumes state.progress entries correspond 1-to-1 with
	// state.scheme.subnetLookups.
	// Note: this implementation assumes a small number of seed specs.
	// For larger numbers, instead of N SubnetLookups, create a single
	// SubnetLookup which returns, for a given IP address, all matching
	// subnets and associated seed specs.
	for index, subnetLookup := range state.scheme.subnetLookups {
		if subnetLookup.ContainsIPAddress(upstreamIPAddress) {
			progressIndexes = append(progressIndexes, index)
		}
	}

	if progressIndexes == nil {
		return nil
	}

	return &ClientSeedPortForward{
		state:           state,
		progressIndexes: progressIndexes,
	}
}

func (state *ClientSeedState) sendIssueSLOKsSignal() {
	if state.signalIssueSLOKs != nil {
		select {
		case state.signalIssueSLOKs <- *new(struct{}):
		default:
		}
	}
}

// UpdateProgress adds port forward bytes transfered and duration to
// all seed spec progresses associated with the port forward.
// If UpdateProgress is invoked after the SLOK time period has rolled
// over, any pending seeded SLOKs are issued and all progress is reset.
// UpdateProgress may be invoked concurrently by many psiphond port
// relay goroutines. The implementation of UpdateProgress prioritizes
// not blocking port forward relaying; a consequence of this lock-free
// design is that progress reported at the exact time of SLOK time period
// rollover may be dropped.
func (portForward *ClientSeedPortForward) UpdateProgress(
	bytesRead, bytesWritten int64, durationNanoseconds int64) {

	// Concurrency: non-blocking -- access to ClientSeedState is unsynchronized
	// to read-only fields, atomic, or channels, except in the case of a time
	// period rollover, in which case a mutex is acquired.

	slokTime := getSLOKTime(portForward.state.scheme.SeedPeriodNanoseconds)

	// If the SLOK time period has changed since progress was last recorded,
	// call issueSLOKs which will issue any SLOKs for that past time period
	// and then clear all progress. Progress will then be recorded for the
	// current time period.
	// As it acquires the state mutex, issueSLOKs may stall other port
	// forwards for this client. The delay is minimized by SLOK caching,
	// which avoids redundant crypto operations.
	if slokTime != atomic.LoadInt64(&portForward.state.progressSLOKTime) {
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
	for _, progressIndex := range portForward.progressIndexes {

		seedSpec := portForward.state.scheme.SeedSpecs[progressIndex]
		progress := portForward.state.progress[progressIndex]

		alreadyExceedsTargets := progress.exceeds(&seedSpec.Targets)

		atomic.AddInt64(&progress.BytesRead, bytesRead)
		atomic.AddInt64(&progress.BytesWritten, bytesWritten)
		atomic.AddInt64(&progress.PortForwardDurationNanoseconds, durationNanoseconds)

		// With the target newly met for a SeedSpec, a new
		// SLOK *may* be issued.
		if !alreadyExceedsTargets && progress.exceeds(&seedSpec.Targets) {
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

	if state.scheme == nil {
		return
	}

	progressSLOKTime := time.Unix(0, state.progressSLOKTime)

	for index, progress := range state.progress {

		seedSpec := state.scheme.SeedSpecs[index]

		if progress.exceeds(&seedSpec.Targets) {

			ref := &slokReference{
				PropagationChannelID: state.propagationChannelID,
				SeedSpecID:           string(seedSpec.ID),
				Time:                 progressSLOKTime,
			}

			state.scheme.derivedSLOKCacheMutex.RLock()
			slok, ok := state.scheme.derivedSLOKCache[*ref]
			state.scheme.derivedSLOKCacheMutex.RUnlock()
			if !ok {
				slok = deriveSLOK(state.scheme, ref)
				state.scheme.derivedSLOKCacheMutex.Lock()
				state.scheme.derivedSLOKCache[*ref] = slok
				state.scheme.derivedSLOKCacheMutex.Unlock()
			}

			// Previously issued SLOKs are not re-added to
			// the payload.
			if state.issuedSLOKs[string(slok.ID)] == nil {
				state.issuedSLOKs[string(slok.ID)] = slok
				state.payloadSLOKs = append(state.payloadSLOKs, slok)
			}
		}
	}

	slokTime := getSLOKTime(state.scheme.SeedPeriodNanoseconds)

	if slokTime != atomic.LoadInt64(&state.progressSLOKTime) {
		atomic.StoreInt64(&state.progressSLOKTime, slokTime)
		// The progress map structure is not reset or modifed; instead
		// the mapped accumulator values are zeroed. Concurrently, port
		// forward relay goroutines continue to add to these accumulators.
		for _, progress := range state.progress {
			atomic.StoreInt64(&progress.BytesRead, 0)
			atomic.StoreInt64(&progress.BytesWritten, 0)
			atomic.StoreInt64(&progress.PortForwardDurationNanoseconds, 0)
		}
	}
}

func getSLOKTime(seedPeriodNanoseconds int64) int64 {
	return time.Now().UTC().Truncate(time.Duration(seedPeriodNanoseconds)).UnixNano()
}

// deriveSLOK produces SLOK secret keys and IDs using HKDF-Expand
// defined in https://tools.ietf.org/html/rfc5869.
func deriveSLOK(
	scheme *Scheme, ref *slokReference) *SLOK {

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

// GetSeedPayload issues any pending SLOKs and returns the accumulated
// SLOKs for a given client. psiphond will calls this when it receives
// signalIssueSLOKs which is the trigger to check for new SLOKs.
// Note: caller must not modify the SLOKs in SeedPayload.SLOKs
// as these are shared data.
func (state *ClientSeedState) GetSeedPayload() *SeedPayload {

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.scheme == nil {
		return &SeedPayload{}
	}

	state.issueSLOKs()

	sloks := make([]*SLOK, len(state.payloadSLOKs))
	for index, slok := range state.payloadSLOKs {
		sloks[index] = slok
	}

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

	// The following fields are ephemeral state.

	oslIDLookup map[string]*OSLFileSpec
}

// An OSLFileSpec includes an ID which is used to reference the
// OSL file and describes the key splits used to divide the OSL
// file key along with the SLOKs required to reassemble those keys.
type OSLFileSpec struct {
	ID        []byte
	KeyShares *KeyShares
}

// KeyShares is a tree data structure which describes the
// key splits used to divide a secret key. BoxedShares are encrypted
// shares of the key, and #Threshold amount of decrypted BoxedShares
// are required to reconstruct the secret key. The keys for BoxedShares
// are either SLOKs (referenced by SLOK ID) or random keys that are
// themselves split as described in child KeyShares.
type KeyShares struct {
	Threshold   int
	BoxedShares [][]byte
	SLOKIDs     [][]byte
	KeyShares   []*KeyShares
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
// epoch. It only returns pave files for OSLs referenced in
// paveServerEntries. paveServerEntries is a list of maps, one for each
// scheme, from the first SLOK time period identifying an OSL to a
// payload to encrypt and pave.
//
// Automation is responsible for consistently distributing server entries
// to OSLs in the case where OSLs are repaved in subsequent calls.
func (config *Config) Pave(
	endTime time.Time,
	propagationChannelID string,
	signingPublicKey string,
	signingPrivateKey string,
	paveServerEntries []map[time.Time]string) ([]*PaveFile, error) {

	config.ReloadableFile.RLock()
	defer config.ReloadableFile.RUnlock()

	var paveFiles []*PaveFile

	registry := &Registry{}

	if len(paveServerEntries) != len(config.Schemes) {
		return nil, common.ContextError(errors.New("invalid paveServerEntries"))
	}

	for schemeIndex, scheme := range config.Schemes {

		slokTimePeriodsPerOSL := 1
		for _, keySplit := range scheme.SeedPeriodKeySplits {
			slokTimePeriodsPerOSL *= keySplit.Total
		}

		if common.Contains(scheme.PropagationChannelIDs, propagationChannelID) {
			oslTime := scheme.epoch
			for !oslTime.After(endTime) {

				firstSLOKTime := oslTime
				fileKey, fileSpec, err := makeOSLFileSpec(
					scheme, propagationChannelID, firstSLOKTime)
				if err != nil {
					return nil, common.ContextError(err)
				}

				registry.FileSpecs = append(registry.FileSpecs, fileSpec)

				serverEntries, ok := paveServerEntries[schemeIndex][oslTime]
				if ok {

					signedServerEntries, err := common.WriteAuthenticatedDataPackage(
						serverEntries,
						signingPublicKey,
						signingPrivateKey)
					if err != nil {
						return nil, common.ContextError(err)
					}

					boxedServerEntries, err := box(fileKey, compress(signedServerEntries))
					if err != nil {
						return nil, common.ContextError(err)
					}

					fileName := fmt.Sprintf(
						OSL_FILENAME_FORMAT, hex.EncodeToString(fileSpec.ID))

					paveFiles = append(paveFiles, &PaveFile{
						Name:     fileName,
						Contents: boxedServerEntries,
					})
				}

				oslTime = oslTime.Add(
					time.Duration(
						int64(slokTimePeriodsPerOSL) * scheme.SeedPeriodNanoseconds))
			}
		}
	}

	registryJSON, err := json.Marshal(registry)
	if err != nil {
		return nil, common.ContextError(err)
	}

	signedRegistry, err := common.WriteAuthenticatedDataPackage(
		base64.StdEncoding.EncodeToString(registryJSON),
		signingPublicKey,
		signingPrivateKey)
	if err != nil {
		return nil, common.ContextError(err)
	}

	paveFiles = append(paveFiles, &PaveFile{
		Name:     REGISTRY_FILENAME,
		Contents: compress(signedRegistry),
	})

	return paveFiles, nil
}

// makeOSLFileSpec creates a random OSL file key, splits it according
// the the scheme's key splits, and sets the OSL ID as its first SLOK
// ID. The returned key is used to encrypt the OSL payload and then
// discarded; the key may be reassembled using the data in the KeyShares
// tree, given sufficient SLOKs.
func makeOSLFileSpec(
	scheme *Scheme,
	propagationChannelID string,
	firstSLOKTime time.Time) ([]byte, *OSLFileSpec, error) {

	ref := &slokReference{
		PropagationChannelID: propagationChannelID,
		SeedSpecID:           string(scheme.SeedSpecs[0].ID),
		Time:                 firstSLOKTime,
	}
	firstSLOK := deriveSLOK(scheme, ref)
	oslID := firstSLOK.ID

	fileKey, err := common.MakeSecureRandomBytes(KEY_LENGTH_BYTES)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	keyShares, err := divideKey(
		scheme,
		fileKey,
		scheme.SeedPeriodKeySplits,
		propagationChannelID,
		&firstSLOKTime)
	if err != nil {
		return nil, nil, common.ContextError(err)
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
	key []byte,
	keySplits []KeySplit,
	propagationChannelID string,
	nextSLOKTime *time.Time) (*KeyShares, error) {

	keySplitIndex := len(keySplits) - 1
	keySplit := keySplits[keySplitIndex]

	shares, err := shamirSplit(key, keySplit.Total, keySplit.Threshold)
	if err != nil {
		return nil, common.ContextError(err)
	}

	var boxedShares [][]byte
	var keyShares []*KeyShares

	for _, share := range shares {
		shareKey, err := common.MakeSecureRandomBytes(KEY_LENGTH_BYTES)
		if err != nil {
			return nil, common.ContextError(err)
		}
		if keySplitIndex > 0 {
			keyShare, err := divideKey(
				scheme,
				shareKey,
				keySplits[0:keySplitIndex],
				propagationChannelID,
				nextSLOKTime)
			if err != nil {
				return nil, common.ContextError(err)
			}
			keyShares = append(keyShares, keyShare)
		} else {
			keyShare, err := divideKeyWithSeedSpecSLOKs(
				scheme,
				shareKey,
				propagationChannelID,
				nextSLOKTime)
			if err != nil {
				return nil, common.ContextError(err)
			}
			keyShares = append(keyShares, keyShare)

			*nextSLOKTime = nextSLOKTime.Add(time.Duration(scheme.SeedPeriodNanoseconds))
		}
		boxedShare, err := box(shareKey, share)
		if err != nil {
			return nil, common.ContextError(err)
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
	key []byte,
	propagationChannelID string,
	nextSLOKTime *time.Time) (*KeyShares, error) {

	var boxedShares [][]byte
	var slokIDs [][]byte

	shares, err := shamirSplit(
		key, len(scheme.SeedSpecs), scheme.SeedSpecThreshold)
	if err != nil {
		return nil, common.ContextError(err)
	}

	for index, seedSpec := range scheme.SeedSpecs {

		ref := &slokReference{
			PropagationChannelID: propagationChannelID,
			SeedSpecID:           string(seedSpec.ID),
			Time:                 *nextSLOKTime,
		}
		slok := deriveSLOK(scheme, ref)

		boxedShare, err := box(slok.Key, shares[index])
		if err != nil {
			return nil, common.ContextError(err)
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

// UnpackRegistry decompresses, validates, and loads a
// JSON encoded OSL registry.
func UnpackRegistry(
	compressedRegistry []byte, signingPublicKey string) (*Registry, []byte, error) {

	packagedRegistry, err := uncompress(compressedRegistry)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	encodedRegistry, err := common.ReadAuthenticatedDataPackage(
		packagedRegistry, signingPublicKey)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	registryJSON, err := base64.StdEncoding.DecodeString(encodedRegistry)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	registry, err := LoadRegistry(registryJSON)
	return registry, registryJSON, err
}

// LoadRegistry loads a JSON encoded OSL registry.
// Clients call this to process downloaded registry files.
func LoadRegistry(registryJSON []byte) (*Registry, error) {

	var registry Registry
	err := json.Unmarshal(registryJSON, &registry)
	if err != nil {
		return nil, common.ContextError(err)
	}

	registry.oslIDLookup = make(map[string]*OSLFileSpec)
	for _, fileSpec := range registry.FileSpecs {
		registry.oslIDLookup[string(fileSpec.ID)] = fileSpec
	}

	return &registry, nil
}

// SLOKLookup is a callback to lookup SLOK keys by ID.
type SLOKLookup func([]byte) []byte

// GetSeededOSLIDs examines each OSL in the registry and returns a list for
// which the client has sufficient SLOKs to reassemble the OSL key and
// decrypt. This function simply does SLOK ID lookups and threshold counting
// and does not derive keys for every OSL.
// The client is responsible for using the resulting list of OSL IDs to fetch
// the OSL files and process.
//
// The client's propagation channel ID is used implicitly: it determines the
// base URL used to download the registry and OSL files. If the client has
// seeded SLOKs from a propagation channel ID different than the one associated
// with its present base URL, they will not appear in the registry and not
// be used.
//
// SLOKLookup is called to determine which SLOKs are seeded with the client.
// errorLogger is a callback to log errors; GetSeededOSLIDs will continue to
// process each candidate OSL even in the case of an error processing a
// particular one.
func (registry *Registry) GetSeededOSLIDs(lookup SLOKLookup, errorLogger func(error)) [][]byte {

	var OSLIDs [][]byte
	for _, fileSpec := range registry.FileSpecs {
		ok, _, err := fileSpec.KeyShares.reassembleKey(lookup, false)
		if err != nil {
			errorLogger(err)
			continue
		}
		if ok {
			OSLIDs = append(OSLIDs, fileSpec.ID)
		}
	}

	return OSLIDs
}

// reassembleKey recursively traverses a KeyShares tree, determining
// whether there exists suffient SLOKs to reassemble the root key and
// performing the key assembly as required.
func (keyShares *KeyShares) reassembleKey(lookup SLOKLookup, unboxKey bool) (bool, []byte, error) {

	if (len(keyShares.SLOKIDs) > 0 && len(keyShares.KeyShares) > 0) ||
		(len(keyShares.SLOKIDs) > 0 && len(keyShares.SLOKIDs) != len(keyShares.BoxedShares)) ||
		(len(keyShares.KeyShares) > 0 && len(keyShares.KeyShares) != len(keyShares.BoxedShares)) {
		return false, nil, common.ContextError(errors.New("unexpected KeyShares format"))
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
					return false, nil, common.ContextError(err)
				}
				shares[i] = share
			}
		}
	} else {
		for i := 0; i < len(keyShares.KeyShares) && shareCount < keyShares.Threshold; i++ {
			ok, key, err := keyShares.KeyShares[i].reassembleKey(lookup, unboxKey)
			if err != nil {
				return false, nil, common.ContextError(err)
			}
			if !ok {
				continue
			}
			shareCount += 1
			if unboxKey {
				share, err := unbox(key, keyShares.BoxedShares[i])
				if err != nil {
					return false, nil, common.ContextError(err)
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

// UnpackOSL reassembles the key for the OSL specified by oslID and uses
// that key to decrypt oslFileContents, uncompress the contents, validate
// the authenticated package, and extract the payload.
// Clients will call UnpackOSL for OSLs indicated by GetSeededOSLIDs along
// with their downloaded content.
// SLOKLookup is called to determine which SLOKs are seeded with the client.
func (registry *Registry) UnpackOSL(
	lookup SLOKLookup,
	oslID []byte,
	oslFileContents []byte,
	signingPublicKey string) (string, error) {

	fileSpec, ok := registry.oslIDLookup[string(oslID)]
	if !ok {
		return "", common.ContextError(errors.New("unknown OSL ID"))
	}

	ok, fileKey, err := fileSpec.KeyShares.reassembleKey(lookup, true)
	if err != nil {
		return "", common.ContextError(err)
	}
	if !ok {
		return "", common.ContextError(errors.New("unseeded OSL"))
	}

	decryptedContents, err := unbox(fileKey, oslFileContents)
	if err != nil {
		return "", common.ContextError(err)
	}

	dataPackage, err := uncompress(decryptedContents)
	if err != nil {
		return "", common.ContextError(err)
	}

	oslPayload, err := common.ReadAuthenticatedDataPackage(
		dataPackage, signingPublicKey)
	if err != nil {
		return "", common.ContextError(err)
	}

	return oslPayload, nil
}

// deriveKeyHKDF implements HKDF-Expand as defined in https://tools.ietf.org/html/rfc5869
// where masterKey = PRK, context = info, and L = 32; SHA-256 is used so HashLen = 32
func deriveKeyHKDF(masterKey []byte, context ...[]byte) []byte {
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
func shamirSplit(secret []byte, total, threshold int) ([][]byte, error) {
	if !isValidShamirSplit(total, threshold) {
		return nil, common.ContextError(errors.New("invalid parameters"))
	}

	if threshold == 1 {
		// Special case: each share is simply the secret
		shares := make([][]byte, total)
		for i := 0; i < total; i++ {
			shares[i] = secret
		}
		return shares, nil
	}

	shareMap, err := sss.Split(byte(total), byte(threshold), secret)
	if err != nil {
		return nil, common.ContextError(err)
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
// A constant  nonce is used, which is secure so long as
// each key is used to encrypt only one message.
func box(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, common.ContextError(errors.New("invalid key length"))
	}
	var nonce [24]byte
	var secretboxKey [32]byte
	copy(secretboxKey[:], key)
	box := secretbox.Seal(nil, plaintext, &nonce, &secretboxKey)
	return box, nil
}

// unbox is a helper wrapper for secretbox.Open
func unbox(key, box []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, common.ContextError(errors.New("invalid key length"))
	}
	var nonce [24]byte
	var secretboxKey [32]byte
	copy(secretboxKey[:], key)
	plaintext, ok := secretbox.Open(nil, box, &nonce, &secretboxKey)
	if !ok {
		return nil, common.ContextError(errors.New("unbox failed"))
	}
	return plaintext, nil
}

func compress(data []byte) []byte {
	var compressedData bytes.Buffer
	writer := zlib.NewWriter(&compressedData)
	writer.Write(data)
	writer.Close()
	return compressedData.Bytes()
}

func uncompress(data []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, common.ContextError(err)
	}
	uncompressedData, err := ioutil.ReadAll(reader)
	reader.Close()
	if err != nil {
		return nil, common.ContextError(err)
	}
	return uncompressedData, nil
}
