/*
 * Copyright (c) 2025, Psiphon Inc.
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
	"fmt"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
	lrucache "github.com/cognusion/go-cache-lru"
)

func TestProxyQualityState(t *testing.T) {
	err := runTestProxyQualityState()
	if err != nil {
		t.Error(errors.Trace(err).Error())
	}
}

func TestProxyQualityReporter(t *testing.T) {
	err := runTestProxyQualityReporter()
	if err != nil {
		t.Error(errors.Trace(err).Error())
	}
}

func runTestProxyQualityState() error {

	qualityTTL := 100 * time.Millisecond
	pendingFailedMatchDeadline := 100 * time.Millisecond
	failedMatchThreshold := 3

	q := NewProxyQuality()

	// Substitute a cache with a much shorter janitor interval, to ensure
	// evictions happen within the artificially short test intervals.
	q.pendingFailedMatches = lrucache.NewWithLRU(0, 1*time.Millisecond, proxyQualityMaxPendingFailedMatches)
	q.pendingFailedMatches.OnEvicted(q.addFailedMatch)

	q.SetParameters(
		qualityTTL, pendingFailedMatchDeadline, failedMatchThreshold)

	testProxyASN := "65537"
	testClientASN1 := "65538"
	testClientASN2 := "65539"
	testClientASN3 := "65540"

	proxyID, err := MakeID()
	if err != nil {
		return errors.Trace(err)
	}

	proxyKey := MakeProxyQualityKey(proxyID, testProxyASN)

	q.AddQuality(proxyKey, ProxyQualityASNCounts{testClientASN1: 1, testClientASN2: 2})

	// Test: HasQuality for any client ASN

	if !q.HasQuality(proxyID, testProxyASN, "") {
		return errors.TraceNew("unexpected HasQuality")
	}

	// Test: HasQuality for specific client ASN

	if !q.HasQuality(proxyID, testProxyASN, testClientASN1) {
		return errors.TraceNew("unexpected HasQuality")
	}

	if q.HasQuality(proxyID, testProxyASN, testClientASN3) {
		return errors.TraceNew("unexpected HasQuality")
	}

	// Test: TTL expires

	time.Sleep(qualityTTL + 1*time.Millisecond)

	if q.HasQuality(proxyID, testProxyASN, "") {
		return errors.TraceNew("unexpected HasQuality")
	}

	// Test: flush

	qualityTTL = proxyQualityTTL

	q.SetParameters(
		qualityTTL, pendingFailedMatchDeadline, failedMatchThreshold)

	q.AddQuality(proxyKey, ProxyQualityASNCounts{testClientASN1: 1, testClientASN2: 2})

	q.Flush()

	if q.HasQuality(proxyID, testProxyASN, "") {
		return errors.TraceNew("unexpected HasQuality")
	}

	// Test: quality removed once failed match threshold reached

	q.AddQuality(proxyKey, ProxyQualityASNCounts{testClientASN1: 1, testClientASN2: 2})

	for i := 0; i < failedMatchThreshold; i++ {

		q.Matched(proxyID, testProxyASN)

		time.Sleep(pendingFailedMatchDeadline + 10*time.Millisecond)

		expectQuality := i < failedMatchThreshold-1

		if q.HasQuality(proxyID, testProxyASN, "") != expectQuality {
			return errors.TraceNew("unexpected HasQuality")
		}
	}

	return nil
}

func runTestProxyQualityReporter() error {

	// This unit test exercises the report queue state, but not the report
	// requests. ProxyQualityReporter.requestScheduler/sendToBrokers are
	// exercised in TestInproxy.

	r, err := NewProxyQualityReporter(
		testutils.NewTestLogger(),
		nil,
		SessionPrivateKey{},
		nil,
		nil,
		nil)
	if err != nil {
		return errors.Trace(err)
	}

	maxEntries := 10
	expectedRequestCount := 2

	r.SetRequestParameters(maxEntries, 0, 0, 0)

	var proxyKeys []ProxyQualityKey
	testProxyASN := "65537"

	for i := 0; i < 20; i++ {
		proxyID, err := MakeID()
		if err != nil {
			return errors.Trace(err)
		}
		proxyKey := MakeProxyQualityKey(proxyID, testProxyASN)
		for j := 0; j < 10; j++ {
			testClientASN := fmt.Sprintf("%d", 65538+j)
			for k := 0; k <= i; k++ {
				r.ReportQuality(
					proxyID, testProxyASN, testClientASN)
			}
		}
		proxyKeys = append(proxyKeys, proxyKey)
	}

	if r.reportQueue.Len() != len(proxyKeys) {
		return errors.TraceNew("unexpected queue size")

	}

	for count := 0; count < expectedRequestCount; count++ {

		requestCounts := r.prepareNextRequest()

		if len(requestCounts) == 0 {
			return errors.TraceNew("unexpected requestCounts")
		}

		for i := count * 10; i < count*10+10; i++ {
			counts, ok := requestCounts[proxyKeys[i]]
			if !ok {
				return errors.TraceNew("missing proxyID")
			}
			for j := 0; j < 10; j++ {
				testClientASN := fmt.Sprintf("%d", 65538+j)
				count, ok := counts[testClientASN]
				if !ok {
					return errors.TraceNew("missing client ASN")
				}
				if count != i+1 {
					return errors.Tracef("unexpected count")
				}
			}
		}

	}

	if len(r.prepareNextRequest()) != 0 {
		return errors.TraceNew("unexpected prepareNextRequest")
	}

	return nil
}
