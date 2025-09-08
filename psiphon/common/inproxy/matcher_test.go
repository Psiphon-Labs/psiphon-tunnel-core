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
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func TestMatcher(t *testing.T) {
	err := runTestMatcher()
	if err != nil {
		t.Error(errors.Trace(err).Error())
	}

}

func runTestMatcher() error {

	limitEntryCount := 50
	rateLimitQuantity := 100
	rateLimitInterval := 1000 * time.Millisecond

	logger := newTestLogger()

	m := NewMatcher(
		&MatcherConfig{
			Logger: logger,

			AnnouncementLimitEntryCount:   limitEntryCount,
			AnnouncementRateLimitQuantity: rateLimitQuantity,
			AnnouncementRateLimitInterval: rateLimitInterval,

			OfferLimitEntryCount:   limitEntryCount,
			OfferRateLimitQuantity: rateLimitQuantity,
			OfferRateLimitInterval: rateLimitInterval,

			ProxyQualityState: NewProxyQuality(),

			AllowMatch: func(common.GeoIPData, common.GeoIPData) bool { return true },
		})
	err := m.Start()
	if err != nil {
		return errors.Trace(err)
	}
	defer m.Stop()

	makeID := func() ID {
		ID, err := MakeID()
		if err != nil {
			panic(err)
		}
		return ID
	}

	makeAnnouncement := func(properties *MatchProperties) *MatchAnnouncement {
		return &MatchAnnouncement{
			Properties:   *properties,
			ProxyID:      makeID(),
			ConnectionID: makeID(),
		}
	}

	makeOffer := func(properties *MatchProperties, useMediaStreams bool) *MatchOffer {
		return &MatchOffer{
			Properties:      *properties,
			UseMediaStreams: useMediaStreams,
		}
	}

	checkMatchMetrics := func(metrics *MatchMetrics) error {
		if metrics.OfferQueueSize < 1 || metrics.AnnouncementQueueSize < 1 {
			return errors.TraceNew("unexpected match metrics")
		}
		return nil
	}

	proxyIP := randomIPAddress()

	proxyFunc := func(
		resultChan chan error,
		proxyIP string,
		matchProperties *MatchProperties,
		timeout time.Duration,
		waitBeforeAnswer chan struct{},
		answerSuccess bool) {

		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()

		announcement := makeAnnouncement(matchProperties)
		offer, matchMetrics, err := m.Announce(ctx, proxyIP, announcement)
		if err != nil {
			resultChan <- errors.Trace(err)
			return
		}
		err = checkMatchMetrics(matchMetrics)
		if err != nil {
			resultChan <- errors.Trace(err)
			return
		}
		_, ok := negotiateProtocolVersion(
			matchProperties.ProtocolVersion,
			offer.Properties.ProtocolVersion,
			offer.UseMediaStreams)
		if !ok {
			resultChan <- errors.TraceNew("unexpected negotiateProtocolVersion failure")
			return
		}

		if waitBeforeAnswer != nil {
			<-waitBeforeAnswer
		}

		if answerSuccess {
			err = m.Answer(
				&MatchAnswer{
					ProxyID:      announcement.ProxyID,
					ConnectionID: announcement.ConnectionID,
				})
		} else {
			m.AnswerError(announcement.ProxyID, announcement.ConnectionID)
		}
		resultChan <- errors.Trace(err)
	}

	clientIP := randomIPAddress()

	baseClientFunc := func(
		resultChan chan error,
		clientIP string,
		matchProperties *MatchProperties,
		useMediaStreams bool,
		timeout time.Duration) {

		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()

		offer := makeOffer(matchProperties, useMediaStreams)
		_, matchAnnouncement, matchMetrics, err := m.Offer(ctx, clientIP, offer)
		if err != nil {
			resultChan <- errors.Trace(err)
			return
		}
		err = checkMatchMetrics(matchMetrics)
		if err != nil {
			resultChan <- errors.Trace(err)
			return
		}
		_, ok := negotiateProtocolVersion(
			matchAnnouncement.Properties.ProtocolVersion,
			offer.Properties.ProtocolVersion,
			offer.UseMediaStreams)
		if !ok {
			resultChan <- errors.TraceNew("unexpected negotiateProtocolVersion failure")
			return
		}

		resultChan <- nil
	}

	clientFunc := func(resultChan chan error, clientIP string,
		matchProperties *MatchProperties, timeout time.Duration) {
		baseClientFunc(resultChan, clientIP, matchProperties, false, timeout)
	}

	clientUsingMediaStreamsFunc := func(resultChan chan error, clientIP string,
		matchProperties *MatchProperties, timeout time.Duration) {
		baseClientFunc(resultChan, clientIP, matchProperties, true, timeout)
	}

	// Test: announce timeout

	proxyResultChan := make(chan error)

	matchProperties := &MatchProperties{
		ProtocolVersion:      LatestProtocolVersion,
		CommonCompartmentIDs: []ID{makeID()},
	}

	go proxyFunc(proxyResultChan, proxyIP, matchProperties, 1*time.Microsecond, nil, true)

	err = <-proxyResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}
	if m.announcementQueue.getLen() != 0 {
		return errors.TraceNew("unexpected queue size")
	}

	// Test: limit announce entries by IP

	time.Sleep(rateLimitInterval)

	maxEntries := limitEntryCount
	maxEntriesProxyResultChan := make(chan error, maxEntries)

	// fill the queue with max entries for one IP; the first one will timeout sooner
	go proxyFunc(maxEntriesProxyResultChan, proxyIP, matchProperties, 10*time.Millisecond, nil, true)
	for i := 0; i < maxEntries-1; i++ {
		go proxyFunc(maxEntriesProxyResultChan, proxyIP, matchProperties, 100*time.Millisecond, nil, true)
	}

	// await goroutines filling queue
	for {
		time.Sleep(10 * time.Microsecond)
		m.announcementQueueMutex.Lock()
		queueLen := m.announcementQueue.getLen()
		m.announcementQueueMutex.Unlock()
		if queueLen == maxEntries {
			break
		}
	}

	// the next enqueue should fail with "max entries"
	go proxyFunc(proxyResultChan, proxyIP, matchProperties, 10*time.Millisecond, nil, true)
	err = <-proxyResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "max entries for IP") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// wait for first entry to timeout
	err = <-maxEntriesProxyResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// now another enqueue succeeds as expected
	go proxyFunc(proxyResultChan, proxyIP, matchProperties, 10*time.Millisecond, nil, true)
	err = <-proxyResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// drain remaining entries
	for i := 0; i < maxEntries-1; i++ {
		err = <-maxEntriesProxyResultChan
		if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
			return errors.Tracef("unexpected result: %v", err)
		}
	}

	// Test: offer timeout

	clientResultChan := make(chan error)

	go clientFunc(clientResultChan, clientIP, matchProperties, 1*time.Microsecond)

	err = <-clientResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}
	if m.offerQueue.Len() != 0 {
		return errors.TraceNew("unexpected queue size")
	}

	// Test: limit offer entries by IP

	time.Sleep(rateLimitInterval)

	maxEntries = limitEntryCount
	maxEntriesClientResultChan := make(chan error, maxEntries)

	// fill the queue with max entries for one IP; the first one will timeout sooner
	go clientFunc(maxEntriesClientResultChan, clientIP, matchProperties, 10*time.Millisecond)
	for i := 0; i < maxEntries-1; i++ {
		go clientFunc(maxEntriesClientResultChan, clientIP, matchProperties, 100*time.Millisecond)
	}

	// await goroutines filling queue
	for {
		time.Sleep(10 * time.Microsecond)

		m.offerQueueMutex.Lock()
		queueLen := m.offerQueue.Len()
		m.offerQueueMutex.Unlock()
		if queueLen == maxEntries {
			break
		}
	}

	// enqueue should fail with "max entries"
	go clientFunc(clientResultChan, clientIP, matchProperties, 10*time.Millisecond)
	err = <-clientResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "max entries for IP") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// wait for first entry to timeout
	err = <-maxEntriesClientResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// now another enqueue succeeds as expected
	go clientFunc(clientResultChan, clientIP, matchProperties, 10*time.Millisecond)
	err = <-clientResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// drain remaining entries
	for i := 0; i < maxEntries-1; i++ {
		err = <-maxEntriesClientResultChan
		if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
			return errors.Tracef("unexpected result: %v", err)
		}
	}

	// Test: announcement rate limit

	m.SetLimits(
		0, rateLimitQuantity, rateLimitInterval, []ID{},
		0, rateLimitQuantity, rateLimitInterval)

	time.Sleep(rateLimitInterval)

	maxEntries = rateLimitQuantity
	maxEntriesProxyResultChan = make(chan error, maxEntries)

	waitGroup := new(sync.WaitGroup)
	for i := 0; i < maxEntries; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			proxyFunc(maxEntriesProxyResultChan, proxyIP, matchProperties, 1*time.Microsecond, nil, true)
		}()
	}

	// Use a wait group to ensure all maxEntries have hit the rate limiter
	// without sleeping before the next attempt, as any sleep can increase
	// the rate limiter token count.
	waitGroup.Wait()

	// the next enqueue should fail with "rate exceeded"
	go proxyFunc(proxyResultChan, proxyIP, matchProperties, 10*time.Millisecond, nil, true)
	err = <-proxyResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "rate exceeded for IP") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// Test: offer rate limit

	maxEntries = rateLimitQuantity
	maxEntriesClientResultChan = make(chan error, maxEntries)

	waitGroup = new(sync.WaitGroup)
	for i := 0; i < rateLimitQuantity; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			clientFunc(maxEntriesClientResultChan, clientIP, matchProperties, 1*time.Microsecond)
		}()
	}

	waitGroup.Wait()

	// enqueue should fail with "rate exceeded"
	go clientFunc(clientResultChan, clientIP, matchProperties, 10*time.Millisecond)
	err = <-clientResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "rate exceeded for IP") {
		return errors.Tracef("unexpected result: %v", err)
	}

	time.Sleep(rateLimitInterval)

	m.SetLimits(
		limitEntryCount, rateLimitQuantity, rateLimitInterval, []ID{},
		limitEntryCount, rateLimitQuantity, rateLimitInterval)

	// Test: basic match

	commonCompartmentIDs := []ID{makeID()}

	geoIPData1 := &MatchProperties{
		ProtocolVersion:      LatestProtocolVersion,
		GeoIPData:            common.GeoIPData{Country: "C1", ASN: "A1"},
		CommonCompartmentIDs: commonCompartmentIDs,
	}

	geoIPData2 := &MatchProperties{
		ProtocolVersion:      LatestProtocolVersion,
		GeoIPData:            common.GeoIPData{Country: "C2", ASN: "A2"},
		CommonCompartmentIDs: commonCompartmentIDs,
	}

	go proxyFunc(proxyResultChan, proxyIP, geoIPData1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, clientIP, geoIPData2, 10*time.Millisecond)

	err = <-proxyResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-clientResultChan
	if err != nil {
		return errors.Trace(err)
	}

	// Test: answer error

	go proxyFunc(proxyResultChan, proxyIP, geoIPData1, 10*time.Millisecond, nil, false)
	go clientFunc(clientResultChan, clientIP, geoIPData2, 10*time.Millisecond)

	err = <-proxyResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-clientResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "no answer") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// Test: client is gone

	waitBeforeAnswer := make(chan struct{})

	go proxyFunc(proxyResultChan, proxyIP, geoIPData1, 100*time.Millisecond, waitBeforeAnswer, true)
	go clientFunc(clientResultChan, clientIP, geoIPData2, 10*time.Millisecond)

	err = <-clientResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	close(waitBeforeAnswer)

	err = <-proxyResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "no pending answer") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// Test: no compartment match

	compartment1 := &MatchProperties{
		ProtocolVersion:      LatestProtocolVersion,
		GeoIPData:            geoIPData1.GeoIPData,
		CommonCompartmentIDs: []ID{makeID()},
	}

	compartment2 := &MatchProperties{
		ProtocolVersion:        LatestProtocolVersion,
		GeoIPData:              geoIPData2.GeoIPData,
		PersonalCompartmentIDs: []ID{makeID()},
	}

	compartment3 := &MatchProperties{
		ProtocolVersion:      LatestProtocolVersion,
		GeoIPData:            geoIPData2.GeoIPData,
		CommonCompartmentIDs: []ID{makeID()},
	}

	compartment4 := &MatchProperties{
		ProtocolVersion:        LatestProtocolVersion,
		GeoIPData:              geoIPData2.GeoIPData,
		PersonalCompartmentIDs: []ID{makeID()},
	}

	proxy1ResultChan := make(chan error)
	proxy2ResultChan := make(chan error)
	client1ResultChan := make(chan error)
	client2ResultChan := make(chan error)

	go proxyFunc(proxy1ResultChan, proxyIP, compartment1, 10*time.Millisecond, nil, true)
	go proxyFunc(proxy2ResultChan, proxyIP, compartment2, 10*time.Millisecond, nil, true)
	go clientFunc(client1ResultChan, clientIP, compartment3, 10*time.Millisecond)
	go clientFunc(client2ResultChan, clientIP, compartment4, 10*time.Millisecond)

	err = <-proxy1ResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	err = <-proxy2ResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	err = <-client1ResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	err = <-client2ResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// Test: common compartment match

	compartment1And3 := &MatchProperties{
		ProtocolVersion: LatestProtocolVersion,
		GeoIPData:       geoIPData2.GeoIPData,
		CommonCompartmentIDs: []ID{
			compartment1.CommonCompartmentIDs[0],
			compartment3.CommonCompartmentIDs[0]},
	}

	go proxyFunc(proxyResultChan, proxyIP, compartment1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, clientIP, compartment1And3, 10*time.Millisecond)

	err = <-proxyResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-clientResultChan
	if err != nil {
		return errors.Trace(err)
	}

	// Test: personal compartment match

	compartment2And4 := &MatchProperties{
		ProtocolVersion: LatestProtocolVersion,
		GeoIPData:       geoIPData2.GeoIPData,
		PersonalCompartmentIDs: []ID{
			compartment2.PersonalCompartmentIDs[0],
			compartment4.PersonalCompartmentIDs[0]},
	}

	go proxyFunc(proxyResultChan, proxyIP, compartment2, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, clientIP, compartment2And4, 10*time.Millisecond)

	err = <-proxyResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-clientResultChan
	if err != nil {
		return errors.Trace(err)
	}

	// Test: no same-ASN match

	go proxyFunc(proxyResultChan, proxyIP, geoIPData1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, clientIP, geoIPData1, 10*time.Millisecond)

	err = <-proxyResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	err = <-clientResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// Test: AllowMatch disallow

	m.config.AllowMatch = func(proxy common.GeoIPData, client common.GeoIPData) bool {
		return proxy != geoIPData1.GeoIPData && client != geoIPData2.GeoIPData
	}

	go proxyFunc(proxyResultChan, proxyIP, compartment1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, clientIP, compartment1And3, 10*time.Millisecond)

	err = <-proxyResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	err = <-clientResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// Test: AllowMatch allow

	m.config.AllowMatch = func(proxy common.GeoIPData, client common.GeoIPData) bool {
		return proxy == geoIPData1.GeoIPData && client == geoIPData2.GeoIPData
	}

	go proxyFunc(proxyResultChan, proxyIP, compartment1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, clientIP, compartment1And3, 10*time.Millisecond)

	err = <-proxyResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-clientResultChan
	if err != nil {
		return errors.Trace(err)
	}

	m.config.AllowMatch = func(proxy common.GeoIPData, client common.GeoIPData) bool {
		return true
	}

	// Test: downgrade-compatible protocol version match

	protocolVersion1 := &MatchProperties{
		ProtocolVersion:      ProtocolVersion1,
		GeoIPData:            common.GeoIPData{Country: "C1", ASN: "A1"},
		CommonCompartmentIDs: commonCompartmentIDs,
	}

	protocolVersion2 := &MatchProperties{
		ProtocolVersion:      ProtocolVersion2,
		GeoIPData:            common.GeoIPData{Country: "C2", ASN: "A2"},
		CommonCompartmentIDs: commonCompartmentIDs,
	}

	go proxyFunc(proxyResultChan, proxyIP, protocolVersion1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, clientIP, protocolVersion2, 10*time.Millisecond)

	err = <-proxyResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-clientResultChan
	if err != nil {
		return errors.Trace(err)
	}

	// Test: no incompatible protocol version match

	go proxyFunc(proxyResultChan, proxyIP, protocolVersion1, 10*time.Millisecond, nil, true)
	go clientUsingMediaStreamsFunc(clientResultChan, clientIP, protocolVersion2, 10*time.Millisecond)

	err = <-proxyResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	err = <-clientResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// Test: downgrade-compatible protocol version match

	// Test: proxy preferred NAT match

	client1Properties := &MatchProperties{
		ProtocolVersion:      LatestProtocolVersion,
		GeoIPData:            common.GeoIPData{Country: "C1", ASN: "A1"},
		NATType:              NATTypeFullCone,
		CommonCompartmentIDs: commonCompartmentIDs,
	}

	client2Properties := &MatchProperties{
		ProtocolVersion:      LatestProtocolVersion,
		GeoIPData:            common.GeoIPData{Country: "C2", ASN: "A2"},
		NATType:              NATTypeSymmetric,
		CommonCompartmentIDs: commonCompartmentIDs,
	}

	proxy1Properties := &MatchProperties{
		ProtocolVersion:      LatestProtocolVersion,
		GeoIPData:            common.GeoIPData{Country: "C3", ASN: "A3"},
		NATType:              NATTypeNone,
		CommonCompartmentIDs: commonCompartmentIDs,
	}

	proxy2Properties := &MatchProperties{
		ProtocolVersion:      LatestProtocolVersion,
		GeoIPData:            common.GeoIPData{Country: "C4", ASN: "A4"},
		NATType:              NATTypeSymmetric,
		CommonCompartmentIDs: commonCompartmentIDs,
	}

	go proxyFunc(proxy1ResultChan, proxyIP, proxy1Properties, 10*time.Millisecond, nil, true)
	go proxyFunc(proxy2ResultChan, proxyIP, proxy2Properties, 10*time.Millisecond, nil, true)
	time.Sleep(5 * time.Millisecond) // Hack to ensure both proxies are enqueued
	go clientFunc(clientResultChan, clientIP, client1Properties, 10*time.Millisecond)

	err = <-proxy1ResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// proxy2 should match since it's the preferred NAT match
	err = <-proxy2ResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-clientResultChan
	if err != nil {
		return errors.Trace(err)
	}

	// Test: client preferred NAT match

	// Limitation: the current Matcher.matchAllOffers logic matches the first
	// enqueued client against the best proxy match, regardless of whether
	// there is another client in the queue that's a better match for that
	// proxy. As a result, this test only passes when the preferred matching
	// client is enqueued first, and the test is currently of limited utility.

	go clientFunc(client2ResultChan, clientIP, client2Properties, 20*time.Millisecond)
	time.Sleep(5 * time.Millisecond) // Hack to ensure client is enqueued
	go clientFunc(client1ResultChan, clientIP, client1Properties, 20*time.Millisecond)
	time.Sleep(5 * time.Millisecond) // Hack to ensure client is enqueued
	go proxyFunc(proxy1ResultChan, proxyIP, proxy1Properties, 20*time.Millisecond, nil, true)

	err = <-proxy1ResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-client1ResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// client2 should match since it's the preferred NAT match
	err = <-client2ResultChan
	if err != nil {
		return errors.Trace(err)
	}

	// Test: priority supercedes preferred NAT match

	go proxyFunc(proxy1ResultChan, proxyIP, proxy1Properties, 10*time.Millisecond, nil, true)
	time.Sleep(5 * time.Millisecond) // Hack to ensure proxy is enqueued
	proxy2Properties.IsPriority = true
	go proxyFunc(proxy2ResultChan, proxyIP, proxy2Properties, 10*time.Millisecond, nil, true)
	time.Sleep(5 * time.Millisecond) // Hack to ensure proxy is enqueued
	go clientFunc(clientResultChan, clientIP, client2Properties, 10*time.Millisecond)

	err = <-proxy1ResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// proxy2 should match since it's the priority, but not preferred NAT match
	err = <-proxy2ResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-clientResultChan
	if err != nil {
		return errors.Trace(err)
	}

	// Test: many matches

	// Reduce test log noise for this phase of the test
	logger.SetLogLevelDebug(false)

	matchCount := 10000
	proxyCount := matchCount
	clientCount := matchCount

	// Buffered so no goroutine will block reporting result
	proxyResultChan = make(chan error, matchCount)
	clientResultChan = make(chan error, matchCount)

	for proxyCount > 0 || clientCount > 0 {

		// Don't simply alternate enqueuing a proxy and a client
		if proxyCount > 0 && (clientCount == 0 || prng.FlipCoin()) {
			go proxyFunc(proxyResultChan, randomIPAddress(), geoIPData1, 10*time.Second, nil, true)
			proxyCount -= 1

		} else if clientCount > 0 {
			go clientFunc(clientResultChan, randomIPAddress(), geoIPData2, 10*time.Second)
			clientCount -= 1
		}
	}

	for i := 0; i < matchCount; i++ {
		err = <-proxyResultChan
		if err != nil {
			return errors.Trace(err)
		}

		err = <-clientResultChan
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

func randomIPAddress() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		prng.Range(0, 255),
		prng.Range(0, 255),
		prng.Range(0, 255),
		prng.Range(0, 255))
}

func TestMatcherMultiQueue(t *testing.T) {
	err := runTestMatcherMultiQueue()
	if err != nil {
		t.Error(errors.Trace(err).Error())
	}
}

func runTestMatcherMultiQueue() error {

	// Test: invalid compartment IDs

	q := newAnnouncementMultiQueue()

	err := q.enqueue(
		&announcementEntry{
			announcement: &MatchAnnouncement{
				Properties: MatchProperties{}}})
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	compartmentID, _ := MakeID()
	err = q.enqueue(
		&announcementEntry{
			announcement: &MatchAnnouncement{
				Properties: MatchProperties{
					CommonCompartmentIDs:   []ID{compartmentID},
					PersonalCompartmentIDs: []ID{compartmentID},
				}}})
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: enqueue multiple candidates

	var otherCommonCompartmentIDs []ID
	var otherPersonalCompartmentIDs []ID

	numOtherCompartmentIDs := 10
	for i := 0; i < numOtherCompartmentIDs; i++ {
		commonCompartmentID, _ := MakeID()
		otherCommonCompartmentIDs = append(
			otherCommonCompartmentIDs, commonCompartmentID)
		personalCompartmentID, _ := MakeID()
		otherPersonalCompartmentIDs = append(
			otherPersonalCompartmentIDs, personalCompartmentID)
	}
	numOtherEntries := 10000
	for i := 0; i < numOtherEntries; i++ {
		ctx, cancel := context.WithDeadline(
			context.Background(), time.Now().Add(time.Duration(i+1)*time.Minute))
		defer cancel()
		err := q.enqueue(
			&announcementEntry{
				ctx: ctx,
				announcement: &MatchAnnouncement{
					Properties: MatchProperties{
						CommonCompartmentIDs: []ID{
							otherCommonCompartmentIDs[i%numOtherCompartmentIDs]},
						NATType: NATTypeSymmetric,
					}}})
		if err != nil {
			return errors.Trace(err)
		}
		err = q.enqueue(
			&announcementEntry{
				ctx: ctx,
				announcement: &MatchAnnouncement{
					Properties: MatchProperties{
						PersonalCompartmentIDs: []ID{
							otherPersonalCompartmentIDs[i%numOtherCompartmentIDs]},
						NATType: NATTypeSymmetric,
					}}})
		if err != nil {
			return errors.Trace(err)
		}
	}

	var matchingCommonCompartmentIDs []ID
	numMatchingCompartmentIDs := 2
	numMatchingEntries := 2
	var expectedMatches []*announcementEntry
	for i := 0; i < numMatchingCompartmentIDs; i++ {
		for j := 0; j < numMatchingEntries; j++ {
			commonCompartmentID, _ := MakeID()
			matchingCommonCompartmentIDs = append(
				matchingCommonCompartmentIDs, commonCompartmentID)
			ctx, cancel := context.WithDeadline(
				context.Background(), time.Now().Add(time.Duration(i+1)*time.Minute))
			defer cancel()
			a := &announcementEntry{
				ctx: ctx,
				announcement: &MatchAnnouncement{
					Properties: MatchProperties{
						CommonCompartmentIDs: matchingCommonCompartmentIDs[i : i+1],
						NATType:              NATTypeNone,
					}}}
			expectedMatches = append(expectedMatches, a)
			err := q.enqueue(a)
			if err != nil {
				return errors.Trace(err)
			}
		}
	}

	// Test: inspect queue state

	if q.getLen() != numOtherEntries*2+numMatchingCompartmentIDs*numMatchingEntries {
		return errors.TraceNew("unexpected total entries count")
	}

	if len(q.commonCompartmentQueues) !=
		numOtherCompartmentIDs+numMatchingCompartmentIDs {
		return errors.TraceNew("unexpected compartment queue count")
	}

	if len(q.personalCompartmentQueues) != numOtherCompartmentIDs {
		return errors.TraceNew("unexpected compartment queue count")
	}

	// Test: find expected matches

	iter := q.startMatching(true, matchingCommonCompartmentIDs)

	if len(iter.compartmentQueues) != numMatchingCompartmentIDs {
		return errors.TraceNew("unexpected iterator state")
	}

	unlimited, partiallyLimited, strictlyLimited := iter.getNATCounts()
	if unlimited != numMatchingCompartmentIDs*numMatchingEntries ||
		partiallyLimited != 0 ||
		strictlyLimited != 0 {
		return errors.TraceNew("unexpected NAT counts")
	}

	match, _ := iter.getNext()
	if match == nil {
		return errors.TraceNew("unexpected missing match")
	}
	if match != expectedMatches[0] {
		return errors.TraceNew("unexpected match")
	}

	if !match.queueReference.dequeue() {
		return errors.TraceNew("unexpected already dequeued")
	}

	if match.queueReference.dequeue() {
		return errors.TraceNew("unexpected not already dequeued")
	}

	iter = q.startMatching(true, matchingCommonCompartmentIDs)

	if len(iter.compartmentQueues) != numMatchingCompartmentIDs {
		return errors.TraceNew("unexpected iterator state")
	}

	unlimited, partiallyLimited, strictlyLimited = iter.getNATCounts()
	if unlimited != numMatchingEntries*numMatchingCompartmentIDs-1 ||
		partiallyLimited != 0 ||
		strictlyLimited != 0 {
		return errors.TraceNew("unexpected NAT counts")
	}

	match, _ = iter.getNext()
	if match == nil {
		return errors.TraceNew("unexpected missing match")
	}
	if match != expectedMatches[1] {
		return errors.TraceNew("unexpected match")
	}

	if !match.queueReference.dequeue() {
		return errors.TraceNew("unexpected already dequeued")
	}

	if len(iter.compartmentQueues) != numMatchingCompartmentIDs {
		return errors.TraceNew("unexpected iterator state")
	}

	// Test: getNext after dequeue

	match, _ = iter.getNext()
	if match == nil {
		return errors.TraceNew("unexpected missing match")
	}
	if match != expectedMatches[2] {
		return errors.TraceNew("unexpected match")
	}

	if !match.queueReference.dequeue() {
		return errors.TraceNew("unexpected already dequeued")
	}

	match, _ = iter.getNext()
	if match == nil {
		return errors.TraceNew("unexpected missing match")
	}
	if match != expectedMatches[3] {
		return errors.TraceNew("unexpected match")
	}

	if !match.queueReference.dequeue() {
		return errors.TraceNew("unexpected already dequeued")
	}

	// Test: reinspect queue state after dequeues

	if q.getLen() != numOtherEntries*2 {
		return errors.TraceNew("unexpected total entries count")
	}

	if len(q.commonCompartmentQueues) != numOtherCompartmentIDs {
		return errors.TraceNew("unexpected compartment queue count")
	}

	if len(q.personalCompartmentQueues) != numOtherCompartmentIDs {
		return errors.TraceNew("unexpected compartment queue count")
	}

	// Test: priority

	q = newAnnouncementMultiQueue()

	var commonCompartmentIDs []ID
	numCompartmentIDs := 10
	for i := 0; i < numCompartmentIDs; i++ {
		commonCompartmentID, _ := MakeID()
		commonCompartmentIDs = append(
			commonCompartmentIDs, commonCompartmentID)
	}

	priorityProxyID, _ := MakeID()
	nonPriorityProxyID, _ := MakeID()

	ctx, cancel := context.WithDeadline(
		context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	numEntries := 10000
	for i := 0; i < numEntries; i++ {
		// Enqueue every other announcement as a priority
		isPriority := i%2 == 0
		proxyID := priorityProxyID
		if !isPriority {
			proxyID = nonPriorityProxyID
		}
		err := q.enqueue(
			&announcementEntry{
				ctx: ctx,
				announcement: &MatchAnnouncement{
					ProxyID: proxyID,
					Properties: MatchProperties{
						IsPriority: isPriority,
						CommonCompartmentIDs: []ID{
							commonCompartmentIDs[prng.Intn(numCompartmentIDs)]},
						NATType: NATTypeUnknown,
					}}})
		if err != nil {
			return errors.Trace(err)
		}
	}

	iter = q.startMatching(true, commonCompartmentIDs)
	for i := 0; i < numEntries; i++ {
		match, isPriority := iter.getNext()
		if match == nil {
			return errors.TraceNew("unexpected missing match")
		}
		// First half, and only first half, of matches is priority
		expectPriority := i < numEntries/2
		if isPriority != expectPriority {
			return errors.TraceNew("unexpected isPriority")
		}
		expectedProxyID := priorityProxyID
		if !expectPriority {
			expectedProxyID = nonPriorityProxyID
		}
		if match.announcement.ProxyID != expectedProxyID {
			return errors.TraceNew("unexpected ProxyID")
		}
		if !match.queueReference.dequeue() {
			return errors.TraceNew("unexpected already dequeued")
		}
	}
	match, _ = iter.getNext()
	if match != nil {
		return errors.TraceNew("unexpected  match")
	}

	return nil
}

// Benchmark numbers for the previous announcement queue implementation, with
// increasingly slow performance when enqueuing and then finding a new,
// distinct personal compartment ID proxy.
//
// pkg: github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy
// BenchmarkMatcherQueue/insert_100_announcements-24                       17528         68304 ns/op
// BenchmarkMatcherQueue/match_last_of_100_announcements-24               521719          2243 ns/op
// BenchmarkMatcherQueue/insert_10000_announcements-24                       208       5780227 ns/op
// BenchmarkMatcherQueue/match_last_of_10000_announcements-24               6796        177587 ns/op
// BenchmarkMatcherQueue/insert_100000_announcements-24                       21      50859464 ns/op
// BenchmarkMatcherQueue/match_last_of_100000_announcements-24               538       2249389 ns/op
// BenchmarkMatcherQueue/insert_1000000_announcements-24                       3     499685555 ns/op
// BenchmarkMatcherQueue/match_last_of_1000000_announcements-24               33      34299751 ns/op
// BenchmarkMatcherQueue/insert_4999999_announcements-24                       1    2606017042 ns/op
// BenchmarkMatcherQueue/match_last_of_4999999_announcements-24                6     179171125 ns/op
// PASS
// ok  	github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy	17.585s
//
// Benchmark numbers for the current implemention, the announcementMultiQueue,
// with constant time performance for the same scenario:
//
// BenchmarkMatcherQueue
// BenchmarkMatcherQueue/insert_100_announcements-24                       15422         77187 ns/op
// BenchmarkMatcherQueue/match_last_of_100_announcements-24               965152          1217 ns/op
// BenchmarkMatcherQueue/insert_10000_announcements-24                       168       7322661 ns/op
// BenchmarkMatcherQueue/match_last_of_10000_announcements-24             906748          1211 ns/op
// BenchmarkMatcherQueue/insert_100000_announcements-24                       16      64770370 ns/op
// BenchmarkMatcherQueue/match_last_of_100000_announcements-24            972342          1243 ns/op
// BenchmarkMatcherQueue/insert_1000000_announcements-24                       2     701046271 ns/op
// BenchmarkMatcherQueue/match_last_of_1000000_announcements-24           988050          1230 ns/op
// BenchmarkMatcherQueue/insert_4999999_announcements-24                       1    4523888833 ns/op
// BenchmarkMatcherQueue/match_last_of_4999999_announcements-24           963894          1186 ns/op
// PASS
// ok  	github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy	22.439s
func BenchmarkMatcherQueue(b *testing.B) {

	SetAllowCommonASNMatching(true)
	defer SetAllowCommonASNMatching(false)

	for _, size := range []int{100, 10000, 100000, 1000000, matcherAnnouncementQueueMaxSize - 1} {

		debug.FreeOSMemory()

		var m *Matcher

		commonCompartmentID, _ := MakeID()

		b.Run(fmt.Sprintf("insert %d announcements", size), func(b *testing.B) {

			for i := 0; i < b.N; i++ {

				// Matcher.Start is not called to start the matchWorker;
				// instead, matchOffer is invoked directly.

				m = NewMatcher(
					&MatcherConfig{
						Logger:     newTestLogger(),
						AllowMatch: func(common.GeoIPData, common.GeoIPData) bool { return true },
					})

				for j := 0; j < size; j++ {

					var commonCompartmentIDs, personalCompartmentIDs []ID
					if prng.FlipCoin() {
						personalCompartmentID, _ := MakeID()
						personalCompartmentIDs = []ID{personalCompartmentID}
					} else {
						commonCompartmentIDs = []ID{commonCompartmentID}
					}

					announcementEntry := &announcementEntry{
						ctx:     context.Background(),
						limitIP: "127.0.0.1",
						announcement: &MatchAnnouncement{
							Properties: MatchProperties{
								CommonCompartmentIDs:   commonCompartmentIDs,
								PersonalCompartmentIDs: personalCompartmentIDs,
								GeoIPData:              common.GeoIPData{},
								NetworkType:            NetworkTypeWiFi,
								NATType:                NATTypePortRestrictedCone,
								PortMappingTypes:       []PortMappingType{},
							},
							ProxyID: ID{},
						},
						offerChan: make(chan *MatchOffer, 1),
					}

					err := m.addAnnouncementEntry(announcementEntry)
					if err != nil {
						b.Fatal(errors.Trace(err).Error())
					}
				}
			}
		})

		b.Run(fmt.Sprintf("match last of %d announcements", size), func(b *testing.B) {

			queueSize := m.announcementQueue.getLen()
			if queueSize != size {
				b.Fatal(errors.Tracef("unexpected queue size: %d", queueSize).Error())
			}

			for i := 0; i < b.N; i++ {

				personalCompartmentID, _ := MakeID()

				announcementEntry :=
					&announcementEntry{
						ctx:     context.Background(),
						limitIP: "127.0.0.1",
						announcement: &MatchAnnouncement{
							Properties: MatchProperties{
								ProtocolVersion:        LatestProtocolVersion,
								PersonalCompartmentIDs: []ID{personalCompartmentID},
								GeoIPData:              common.GeoIPData{},
								NetworkType:            NetworkTypeWiFi,
								NATType:                NATTypePortRestrictedCone,
								PortMappingTypes:       []PortMappingType{},
							},
							ProxyID: ID{},
						},
						offerChan: make(chan *MatchOffer, 1),
					}

				offerEntry := &offerEntry{
					ctx:     context.Background(),
					limitIP: "127.0.0.1",
					offer: &MatchOffer{
						Properties: MatchProperties{
							ProtocolVersion:        LatestProtocolVersion,
							PersonalCompartmentIDs: []ID{personalCompartmentID},
							GeoIPData:              common.GeoIPData{},
							NetworkType:            NetworkTypeWiFi,
							NATType:                NATTypePortRestrictedCone,
							PortMappingTypes:       []PortMappingType{},
						},
					},
					answerChan: make(chan *answerInfo, 1),
				}

				err := m.addAnnouncementEntry(announcementEntry)
				if err != nil {
					b.Fatal(errors.Trace(err).Error())
				}

				match, _ := m.matchOffer(offerEntry)
				if match == nil {
					b.Fatal(errors.TraceNew("unexpected no match").Error())
				}

				m.removeAnnouncementEntry(false, match)
			}
		})
	}
}
