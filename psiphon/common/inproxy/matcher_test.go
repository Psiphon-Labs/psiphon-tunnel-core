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
	"strings"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func TestMatcher(t *testing.T) {
	err := runTestMatcher()
	if err != nil {
		t.Errorf(errors.Trace(err).Error())
	}

}

func runTestMatcher() error {

	limitEntryCount := 50
	rateLimitQuantity := 100
	rateLimitInterval := 500 * time.Millisecond

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

	makeOffer := func(properties *MatchProperties) *MatchOffer {
		return &MatchOffer{
			Properties:                 *properties,
			ClientProxyProtocolVersion: ProxyProtocolVersion1,
		}
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
		offer, err := m.Announce(ctx, proxyIP, announcement)
		if err != nil {
			resultChan <- errors.Trace(err)
			return
		}

		if waitBeforeAnswer != nil {
			<-waitBeforeAnswer
		}

		if answerSuccess {
			err = m.Answer(
				&MatchAnswer{
					ProxyID:                      announcement.ProxyID,
					ConnectionID:                 announcement.ConnectionID,
					SelectedProxyProtocolVersion: offer.ClientProxyProtocolVersion,
				})
		} else {
			m.AnswerError(announcement.ProxyID, announcement.ConnectionID)
		}
		resultChan <- errors.Trace(err)
	}

	clientIP := randomIPAddress()

	clientFunc := func(
		resultChan chan error,
		clientIP string,
		matchProperties *MatchProperties,
		timeout time.Duration) {

		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()

		offer := makeOffer(matchProperties)
		answer, _, err := m.Offer(ctx, clientIP, offer)
		if err != nil {
			resultChan <- errors.Trace(err)
			return
		}
		if answer.SelectedProxyProtocolVersion != offer.ClientProxyProtocolVersion {
			resultChan <- errors.TraceNew("unexpected selected proxy protocol version")
			return
		}
		resultChan <- nil
	}

	// Test: announce timeout

	proxyResultChan := make(chan error)

	go proxyFunc(proxyResultChan, proxyIP, &MatchProperties{}, 1*time.Microsecond, nil, true)

	err = <-proxyResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}
	if m.announcementQueue.Len() != 0 {
		return errors.TraceNew("unexpected queue size")
	}

	// Test: limit announce entries by IP

	time.Sleep(rateLimitInterval)

	maxEntries := limitEntryCount
	maxEntriesProxyResultChan := make(chan error, maxEntries)

	// fill the queue with max entries for one IP; the first one will timeout sooner
	go proxyFunc(maxEntriesProxyResultChan, proxyIP, &MatchProperties{}, 10*time.Millisecond, nil, true)
	for i := 0; i < maxEntries-1; i++ {
		go proxyFunc(maxEntriesProxyResultChan, proxyIP, &MatchProperties{}, 100*time.Millisecond, nil, true)
	}

	// await goroutines filling queue
	for {
		time.Sleep(10 * time.Microsecond)
		m.announcementQueueMutex.Lock()
		queueLen := m.announcementQueue.Len()
		m.announcementQueueMutex.Unlock()
		if queueLen == maxEntries {
			break
		}
	}

	// the next enqueue should fail with "max entries"
	go proxyFunc(proxyResultChan, proxyIP, &MatchProperties{}, 10*time.Millisecond, nil, true)
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
	go proxyFunc(proxyResultChan, proxyIP, &MatchProperties{}, 10*time.Millisecond, nil, true)
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

	go clientFunc(clientResultChan, clientIP, &MatchProperties{}, 1*time.Microsecond)

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
	go clientFunc(maxEntriesClientResultChan, clientIP, &MatchProperties{}, 10*time.Millisecond)
	for i := 0; i < maxEntries-1; i++ {
		go clientFunc(maxEntriesClientResultChan, clientIP, &MatchProperties{}, 100*time.Millisecond)
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
	go clientFunc(clientResultChan, clientIP, &MatchProperties{}, 10*time.Millisecond)
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
	go clientFunc(clientResultChan, clientIP, &MatchProperties{}, 10*time.Millisecond)
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

	for i := 0; i < maxEntries; i++ {
		go proxyFunc(maxEntriesProxyResultChan, proxyIP, &MatchProperties{}, 1*time.Microsecond, nil, true)
	}

	time.Sleep(rateLimitInterval / 2)

	// the next enqueue should fail with "rate exceeded"
	go proxyFunc(proxyResultChan, proxyIP, &MatchProperties{}, 10*time.Millisecond, nil, true)
	err = <-proxyResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "rate exceeded for IP") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// Test: offer rate limit

	maxEntries = rateLimitQuantity
	maxEntriesClientResultChan = make(chan error, maxEntries)

	for i := 0; i < rateLimitQuantity; i++ {
		go clientFunc(maxEntriesClientResultChan, clientIP, &MatchProperties{}, 1*time.Microsecond)
	}

	time.Sleep(rateLimitInterval / 2)

	// enqueue should fail with "rate exceeded"
	go clientFunc(clientResultChan, clientIP, &MatchProperties{}, 10*time.Millisecond)
	err = <-clientResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "rate exceeded for IP") {
		return errors.Tracef("unexpected result: %v", err)
	}

	time.Sleep(rateLimitInterval)

	m.SetLimits(
		limitEntryCount, rateLimitQuantity, rateLimitInterval, []ID{},
		limitEntryCount, rateLimitQuantity, rateLimitInterval)

	// Test: basic match

	basicCommonCompartmentIDs := []ID{makeID()}

	geoIPData1 := &MatchProperties{
		GeoIPData:            common.GeoIPData{Country: "C1", ASN: "A1"},
		CommonCompartmentIDs: basicCommonCompartmentIDs,
	}

	geoIPData2 := &MatchProperties{
		GeoIPData:            common.GeoIPData{Country: "C2", ASN: "A2"},
		CommonCompartmentIDs: basicCommonCompartmentIDs,
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
	if err == nil || !strings.HasSuffix(err.Error(), "no client") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// Test: no compartment match

	compartment1 := &MatchProperties{
		GeoIPData:              geoIPData1.GeoIPData,
		CommonCompartmentIDs:   []ID{makeID()},
		PersonalCompartmentIDs: []ID{makeID()},
	}

	compartment2 := &MatchProperties{
		GeoIPData:              geoIPData2.GeoIPData,
		CommonCompartmentIDs:   []ID{makeID()},
		PersonalCompartmentIDs: []ID{makeID()},
	}

	go proxyFunc(proxyResultChan, proxyIP, compartment1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, clientIP, compartment2, 10*time.Millisecond)

	err = <-proxyResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	err = <-clientResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// Test: common compartment match

	compartment1And2 := &MatchProperties{
		GeoIPData:            geoIPData2.GeoIPData,
		CommonCompartmentIDs: []ID{compartment1.CommonCompartmentIDs[0], compartment2.CommonCompartmentIDs[0]},
	}

	go proxyFunc(proxyResultChan, proxyIP, compartment1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, clientIP, compartment1And2, 10*time.Millisecond)

	err = <-proxyResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-clientResultChan
	if err != nil {
		return errors.Trace(err)
	}

	// Test: personal compartment match

	compartment1And2 = &MatchProperties{
		GeoIPData:              geoIPData2.GeoIPData,
		PersonalCompartmentIDs: []ID{compartment1.PersonalCompartmentIDs[0], compartment2.PersonalCompartmentIDs[0]},
	}

	go proxyFunc(proxyResultChan, proxyIP, compartment1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, clientIP, compartment1And2, 10*time.Millisecond)

	err = <-proxyResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-clientResultChan
	if err != nil {
		return errors.Trace(err)
	}

	// Test: personal compartment preferred match

	compartment1Common := &MatchProperties{
		GeoIPData:            geoIPData1.GeoIPData,
		CommonCompartmentIDs: []ID{compartment1.CommonCompartmentIDs[0]},
	}

	compartment1Personal := &MatchProperties{
		GeoIPData:              geoIPData1.GeoIPData,
		PersonalCompartmentIDs: []ID{compartment1.PersonalCompartmentIDs[0]},
	}

	compartment1CommonAndPersonal := &MatchProperties{
		GeoIPData:              geoIPData2.GeoIPData,
		CommonCompartmentIDs:   []ID{compartment1.CommonCompartmentIDs[0]},
		PersonalCompartmentIDs: []ID{compartment1.PersonalCompartmentIDs[0]},
	}

	client1ResultChan := make(chan error)
	client2ResultChan := make(chan error)

	proxy1ResultChan := make(chan error)
	proxy2ResultChan := make(chan error)

	go proxyFunc(proxy1ResultChan, proxyIP, compartment1Common, 10*time.Millisecond, nil, true)
	go proxyFunc(proxy2ResultChan, proxyIP, compartment1Personal, 10*time.Millisecond, nil, true)
	time.Sleep(5 * time.Millisecond) // Hack to ensure both proxies are enqueued
	go clientFunc(client1ResultChan, clientIP, compartment1CommonAndPersonal, 10*time.Millisecond)

	err = <-proxy1ResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// proxy2 should match since it has the preferred personal compartment ID
	err = <-proxy2ResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-client1ResultChan
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

	// Test: proxy preferred NAT match

	client1Properties := &MatchProperties{
		GeoIPData:            common.GeoIPData{Country: "C1", ASN: "A1"},
		NATType:              NATTypeFullCone,
		CommonCompartmentIDs: basicCommonCompartmentIDs,
	}

	client2Properties := &MatchProperties{
		GeoIPData:            common.GeoIPData{Country: "C2", ASN: "A2"},
		NATType:              NATTypeSymmetric,
		CommonCompartmentIDs: basicCommonCompartmentIDs,
	}

	proxy1Properties := &MatchProperties{
		GeoIPData:            common.GeoIPData{Country: "C3", ASN: "A3"},
		NATType:              NATTypeNone,
		CommonCompartmentIDs: basicCommonCompartmentIDs,
	}

	proxy2Properties := &MatchProperties{
		GeoIPData:            common.GeoIPData{Country: "C4", ASN: "A4"},
		NATType:              NATTypeSymmetric,
		CommonCompartmentIDs: basicCommonCompartmentIDs,
	}

	go proxyFunc(proxy1ResultChan, proxyIP, proxy1Properties, 10*time.Millisecond, nil, true)
	go proxyFunc(proxy2ResultChan, proxyIP, proxy2Properties, 10*time.Millisecond, nil, true)
	time.Sleep(5 * time.Millisecond) // Hack to ensure both proxies are enqueued
	go clientFunc(client1ResultChan, clientIP, client1Properties, 10*time.Millisecond)

	err = <-proxy1ResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// proxy2 should match since it's the preferred NAT match
	err = <-proxy2ResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-client1ResultChan
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
	time.Sleep(5 * time.Millisecond) // Hack to client is enqueued
	go clientFunc(client1ResultChan, clientIP, client1Properties, 20*time.Millisecond)
	time.Sleep(5 * time.Millisecond) // Hack to client is enqueued
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
