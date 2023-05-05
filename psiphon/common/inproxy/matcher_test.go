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

	logger := newTestLogger()

	m := NewMatcher(
		&MatcherConfig{
			Logger: logger,
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

	proxyFunc := func(
		resultChan chan error,
		matchProperties *MatchProperties,
		timeout time.Duration,
		waitBeforeAnswer chan struct{},
		answerSuccess bool) {

		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()

		announcement := makeAnnouncement(matchProperties)
		offer, err := m.Announce(ctx, announcement)
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

	clientFunc := func(
		resultChan chan error,
		matchProperties *MatchProperties,
		timeout time.Duration) {

		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()

		offer := makeOffer(matchProperties)
		answer, _, err := m.Offer(ctx, offer)
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

	go proxyFunc(proxyResultChan, &MatchProperties{}, 1*time.Microsecond, nil, true)

	err = <-proxyResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}
	if m.announcementQueue.Len() != 0 {
		return errors.TraceNew("unexpected queue size")
	}

	// Test: offer timeout

	clientResultChan := make(chan error)

	go clientFunc(clientResultChan, &MatchProperties{}, 1*time.Microsecond)

	err = <-clientResultChan
	if err == nil || !strings.HasSuffix(err.Error(), "context deadline exceeded") {
		return errors.Tracef("unexpected result: %v", err)
	}
	if m.offerQueue.Len() != 0 {
		return errors.TraceNew("unexpected queue size")
	}

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

	go proxyFunc(proxyResultChan, geoIPData1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, geoIPData2, 10*time.Millisecond)

	err = <-proxyResultChan
	if err != nil {
		return errors.Trace(err)
	}

	err = <-clientResultChan
	if err != nil {
		return errors.Trace(err)
	}

	// Test: answer error

	go proxyFunc(proxyResultChan, geoIPData1, 10*time.Millisecond, nil, false)
	go clientFunc(clientResultChan, geoIPData2, 10*time.Millisecond)

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

	go proxyFunc(proxyResultChan, geoIPData1, 100*time.Millisecond, waitBeforeAnswer, true)
	go clientFunc(clientResultChan, geoIPData2, 10*time.Millisecond)

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

	go proxyFunc(proxyResultChan, compartment1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, compartment2, 10*time.Millisecond)

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

	go proxyFunc(proxyResultChan, compartment1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, compartment1And2, 10*time.Millisecond)

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

	go proxyFunc(proxyResultChan, compartment1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, compartment1And2, 10*time.Millisecond)

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

	go proxyFunc(proxy1ResultChan, compartment1Common, 10*time.Millisecond, nil, true)
	go proxyFunc(proxy2ResultChan, compartment1Personal, 10*time.Millisecond, nil, true)
	time.Sleep(5 * time.Millisecond) // Hack to ensure both proxies are enqueued
	go clientFunc(client1ResultChan, compartment1CommonAndPersonal, 10*time.Millisecond)

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

	go proxyFunc(proxyResultChan, geoIPData1, 10*time.Millisecond, nil, true)
	go clientFunc(clientResultChan, geoIPData1, 10*time.Millisecond)

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

	go proxyFunc(proxy1ResultChan, proxy1Properties, 10*time.Millisecond, nil, true)
	go proxyFunc(proxy2ResultChan, proxy2Properties, 10*time.Millisecond, nil, true)
	time.Sleep(5 * time.Millisecond) // Hack to ensure both proxies are enqueued
	go clientFunc(client1ResultChan, client1Properties, 10*time.Millisecond)

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

	go proxyFunc(client1ResultChan, client1Properties, 10*time.Millisecond, nil, true)
	go proxyFunc(client2ResultChan, client2Properties, 10*time.Millisecond, nil, true)
	time.Sleep(500 * time.Microsecond) // Hack to ensure both clients are enqueued
	go clientFunc(proxy1ResultChan, proxy1Properties, 10*time.Millisecond)

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
			go proxyFunc(proxyResultChan, geoIPData1, 10*time.Second, nil, true)
			proxyCount -= 1

		} else if clientCount > 0 {
			go clientFunc(clientResultChan, geoIPData2, 10*time.Second)
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
