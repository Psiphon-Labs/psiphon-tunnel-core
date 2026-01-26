/*
 * Copyright (c) 2026, Psiphon Inc.
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

const (
	destBytesSoftMaxEntries = 100000
	destBytesHardMaxEntries = 1000000
)

// destBytesLogger accumulates ASN and domain destination bytes metrics,
// aggregates into coarse-grained buckets, and periodically logs destination
// byte events.
type destBytesLogger struct {
	support *SupportServices

	runMutex      sync.Mutex
	running       bool
	stopBroadcast chan struct{}
	waitGroup     *sync.WaitGroup

	asnBytesMutex sync.Mutex
	asnBytes      map[destBytesBucket]destBytesCounters

	domainBytesMutex sync.Mutex
	domainBytes      map[destBytesBucket]destBytesCounters

	signalLogASNBytes    chan struct{}
	signalLogDomainBytes chan struct{}
	loggedHardMax        atomic.Bool
}

type destBytesBucket struct {
	destination    string
	clientRegion   string
	clientASN      string
	sponsorID      string
	clientPlatform string
	deviceRegion   string
}

type destBytesCounters struct {
	TCP int64
	UDP int64
}

// newDestBytesLogger initializes a new destBytesLogger.
func newDestBytesLogger(support *SupportServices) *destBytesLogger {
	return &destBytesLogger{
		support:              support,
		asnBytes:             make(map[destBytesBucket]destBytesCounters),
		domainBytes:          make(map[destBytesBucket]destBytesCounters),
		signalLogASNBytes:    make(chan struct{}, 1),
		signalLogDomainBytes: make(chan struct{}, 1),
	}
}

// Start begins the periodic logging worker.
func (d *destBytesLogger) Start() error {

	d.runMutex.Lock()
	defer d.runMutex.Unlock()

	if d.running {
		return errors.TraceNew("already running")
	}

	d.running = true
	d.stopBroadcast = make(chan struct{})
	d.waitGroup = new(sync.WaitGroup)

	d.waitGroup.Add(1)
	go func() {
		defer d.waitGroup.Done()
		d.run()
	}()

	return nil
}

// Stop halts the periodic logging worker. Any remaining aggregated metrics
// will be logged before Stop returns.
func (d *destBytesLogger) Stop() {

	d.runMutex.Lock()
	defer d.runMutex.Unlock()

	if !d.running {
		return
	}

	close(d.stopBroadcast)
	d.waitGroup.Wait()

	d.running = false
	d.stopBroadcast = nil
	d.waitGroup = nil
}

// AddASNBytes adds ASN destination bytes to the aggregation.
func (d *destBytesLogger) AddASNBytes(
	destination string,
	clientGeoIPData GeoIPData,
	apiParams common.APIParameters,
	bytesTCP int64,
	bytesUDP int64) {

	if d == nil {
		// !RunDestBytesLogger case.
		return
	}

	d.addBytes(
		true,
		destination,
		clientGeoIPData,
		apiParams,
		bytesTCP,
		bytesUDP)
}

// AddDomainBytes adds domain destination bytes to the aggregation.
func (d *destBytesLogger) AddDomainBytes(
	destination string,
	clientGeoIPData GeoIPData,
	apiParams common.APIParameters,
	bytesTCP int64,
	bytesUDP int64) {

	if d == nil {
		// !RunDestBytesLogger case.
		return
	}

	d.addBytes(
		false,
		destination,
		clientGeoIPData,
		apiParams,
		bytesTCP,
		bytesUDP)
}

func (d *destBytesLogger) run() {

	ticker := time.NewTicker(d.support.Config.destinationBytesPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.logAccumulatedASNDestBytes()
			d.logAccumulatedDomainDestBytes()
		case <-d.signalLogASNBytes:
			d.logAccumulatedASNDestBytes()
		case <-d.signalLogDomainBytes:
			d.logAccumulatedDomainDestBytes()
		case <-d.stopBroadcast:
			// Log on stop to record metrics accumulated since the last
			// periodic logging.
			d.logAccumulatedASNDestBytes()
			d.logAccumulatedDomainDestBytes()
			return
		}
	}
}

func (d *destBytesLogger) logAccumulatedASNDestBytes() {

	// Take a snapshot of the aggregation, and then unlock immediately to
	// avoid blocking addBytes calls while logging.
	//
	// Resetting the aggregation here also frees memory associated with rarer
	// buckets that don't reoccur often.

	d.asnBytesMutex.Lock()
	asnBytes := d.asnBytes
	d.asnBytes = make(map[destBytesBucket]destBytesCounters)
	d.asnBytesMutex.Unlock()

	for bucket, counters := range asnBytes {
		logFields := make(LogFields)
		logFields["event_name"] = "asn_dest_bytes"
		logFields["asn"] = bucket.destination
		d.addLogFields(logFields, bucket, counters)
		log.LogRawFieldsWithTimestamp(logFields)
	}
}

func (d *destBytesLogger) logAccumulatedDomainDestBytes() {

	// See snapshot comment in logAccumulatedDomainDestBytes.

	d.domainBytesMutex.Lock()
	domainBytes := d.domainBytes
	d.domainBytes = make(map[destBytesBucket]destBytesCounters)
	d.domainBytesMutex.Unlock()

	for bucket, counters := range domainBytes {
		logFields := make(LogFields)
		logFields["event_name"] = "domain_dest_bytes"
		logFields["domain"] = bucket.destination
		d.addLogFields(logFields, bucket, counters)
		log.LogRawFieldsWithTimestamp(logFields)
	}
}

func (d *destBytesLogger) addLogFields(
	logFields LogFields,
	bucket destBytesBucket,
	counters destBytesCounters) {

	logFields["client_region"] = bucket.clientRegion
	logFields["client_asn"] = bucket.clientASN
	logFields["sponsor_id"] = bucket.sponsorID
	logFields["client_platform"] = bucket.clientPlatform
	logFields["device_region"] = bucket.deviceRegion

	logFields["bytes_tcp"] = counters.TCP
	logFields["bytes_udp"] = counters.UDP
	logFields["bytes"] = counters.TCP + counters.UDP
}

func (d *destBytesLogger) addBytes(
	isASN bool,
	destination string,
	clientGeoIPData GeoIPData,
	apiParams common.APIParameters,
	bytesTCP int64,
	bytesUDP int64) {

	if bytesTCP == 0 && bytesUDP == 0 {
		// Some cases, such as client submitted domain bytes, may report all 0
		// bytes. Skip this data.
		return
	}

	sponsorID, _ := getOptionalStringRequestParam(apiParams, "sponsor_id")
	clientPlatform, _ := getOptionalStringRequestParam(apiParams, "client_platform")
	deviceRegion, _ := getOptionalStringRequestParam(apiParams, "device_region")

	bucket := destBytesBucket{
		destination:    destination,
		clientRegion:   clientGeoIPData.Country,
		clientASN:      clientGeoIPData.ASN,
		sponsorID:      sponsorID,
		clientPlatform: normalizeClientPlatform(clientPlatform),
		deviceRegion:   deviceRegion,
	}

	// The map key is a comparable struct of strings. The non-pointer struct
	// types used for the map keys and values avoids allocations.

	var destBytes map[destBytesBucket]destBytesCounters
	var logSignal chan struct{}

	if isASN {
		d.asnBytesMutex.Lock()
		defer d.asnBytesMutex.Unlock()

		destBytes = d.asnBytes
		logSignal = d.signalLogASNBytes

	} else {
		d.domainBytesMutex.Lock()
		defer d.domainBytesMutex.Unlock()

		destBytes = d.domainBytes
		logSignal = d.signalLogDomainBytes
	}

	counters, ok := destBytes[bucket]

	if !ok {

		// A new aggregation map entry will be added. To avoid the map getting
		// too large, signal an immediate log dump without awaiting the next
		// period.
		//
		// When the soft limit is reached, logging is signaled. If the hard
		// limit is reached, the new data is dropped.

		count := len(destBytes)

		if count >= destBytesSoftMaxEntries {
			select {
			case logSignal <- struct{}{}:
			default:
			}
		}

		if count >= destBytesHardMaxEntries {
			if d.loggedHardMax.CompareAndSwap(false, true) {
				log.WithTrace().Warning("destBytesLogger hard max exceeded")
			}
			return
		}
	}

	counters.TCP += bytesTCP
	counters.UDP += bytesUDP

	destBytes[bucket] = counters
}
