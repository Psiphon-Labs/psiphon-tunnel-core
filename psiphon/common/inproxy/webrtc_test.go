//go:build !PSIPHON_DISABLE_INPROXY

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

package inproxy

import (
	"context"
	"testing"
	"time"

	"github.com/Psiphon-Labs/pion-ice/v4"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/pion/transport/v4/vnet"
	"golang.org/x/sync/errgroup"
)

func TestMakeICEKeepaliveSchedule(t *testing.T) {

	// Check that every supported DTLS fingerprint has a corresponding ICE
	// keep alive schedule.

	for _, fingerprint := range protocol.SupportedDTLSFingerprints {
		t.Run(fingerprint, func(t *testing.T) {
			for _, isOffer := range []bool{true, false} {
				_, _, err := makeICEKeepaliveSchedule(fingerprint, ObfuscationSecret{}, isOffer)
				if err != nil {
					t.Fatalf("makeICEKeepaliveSchedule failed: isOffer=%t: %v", isOffer, err)
				}
			}
		})
	}
}

func TestICEKeepaliveTiming(t *testing.T) {

	testCases := []struct {
		fingerprint              string
		minInterval, maxInterval time.Duration
		jitter                   float64
	}{
		{protocol.DTLS_FINGERPRINT_CHROME_138, 2500 * time.Millisecond, 2500 * time.Millisecond, 0},
		{protocol.DTLS_FINGERPRINT_FIREFOX_148, 5 * time.Second, 5 * time.Second, 0.2},
		{protocol.DTLS_FINGERPRINT_RANDOMIZED, 5 * time.Second, 10 * time.Second, 0.2},
	}

	// Exercise each fingerprint in both ICE roles against a different schedule.
	for i, testCase := range testCases {
		t.Run(testCase.fingerprint, func(t *testing.T) {
			router, err := vnet.NewRouter(&vnet.RouterConfig{
				CIDR:          "192.0.2.0/24",
				LoggerFactory: logging.NewDefaultLoggerFactory(),
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { router.Stop() })

			var networks [2]*vnet.Net
			for j := range networks {
				networks[j], err = vnet.NewNet(&vnet.NetConfig{})
				if err != nil {
					t.Fatal(err)
				}
				if err := router.AddNet(networks[j]); err != nil {
					t.Fatal(err)
				}
			}
			// vnet's MAC address allocation is not safe for concurrent use.
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			type bindingRequest struct {
				sender int
				at     time.Time
			}
			requests := make(chan bindingRequest, 128)
			var agents [2]*ice.Agent
			var minIntervals, maxIntervals [2]time.Duration
			for j := range agents {
				testCase := testCases[(i+j)%len(testCases)]
				interval, jitter, err := makeICEKeepaliveSchedule(
					testCase.fingerprint, ObfuscationSecret{}, j == 0)
				if err != nil {
					t.Fatal(err)
				}
				if interval < testCase.minInterval || interval > testCase.maxInterval || jitter != testCase.jitter {
					t.Fatalf("%s isOffer=%t: unexpected schedule: %s, jitter=%g",
						testCase.fingerprint, j == 0, interval, jitter)
				}
				const tolerance = 250 * time.Millisecond
				minIntervals[j] = time.Duration(float64(interval)*(1-jitter)) - tolerance
				maxIntervals[j] = time.Duration(float64(interval)*(1+jitter)) + tolerance

				agent, err := ice.NewAgentWithOptions(
					ice.WithNet(networks[j]),
					ice.WithNetworkTypes([]ice.NetworkType{ice.NetworkTypeUDP4}),
					ice.WithCandidateTypes([]ice.CandidateType{ice.CandidateTypeHost}),
					ice.WithMulticastDNSMode(ice.MulticastDNSModeDisabled),
					ice.WithDisconnectedTimeout(45*time.Second),
					ice.WithFailedTimeout(0),
					ice.WithKeepaliveInterval(interval),
					ice.WithKeepaliveIntervalJitter(jitter),
					ice.WithBindingRequestHandler(func(_ *stun.Message, _, _ ice.Candidate, _ *ice.CandidatePair) bool {
						select {
						case requests <- bindingRequest{sender: 1 - j, at: time.Now()}:
						case <-ctx.Done():
						}
						return false
					}),
				)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { agent.Close() })
				agents[j] = agent
			}
			if err := router.Start(); err != nil {
				t.Fatal(err)
			}

			var ufrags, passwords [2]string
			for j, agent := range agents {
				gathered := make(chan struct{})
				if err := agent.OnCandidate(func(candidate ice.Candidate) {
					if candidate == nil {
						close(gathered)
					}
				}); err != nil {
					t.Fatal(err)
				}
				if err := agent.GatherCandidates(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-gathered:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				candidates, err := agent.GetLocalCandidates()
				if err != nil {
					t.Fatal(err)
				}
				for _, candidate := range candidates {
					remote, err := ice.UnmarshalCandidate(candidate.Marshal())
					if err != nil {
						t.Fatal(err)
					}
					if err := agents[1-j].AddRemoteCandidate(remote); err != nil {
						t.Fatal(err)
					}
				}
				ufrags[j], passwords[j], err = agent.GetLocalUserCredentials()
				if err != nil {
					t.Fatal(err)
				}
			}

			group, connectCtx := errgroup.WithContext(ctx)
			group.Go(func() error {
				_, err := agents[0].Dial(connectCtx, ufrags[1], passwords[1])
				return err
			})
			group.Go(func() error {
				_, err := agents[1].Accept(connectCtx, ufrags[0], passwords[0])
				return err
			})
			if err := group.Wait(); err != nil {
				t.Fatal(err)
			}

			// Exclude startup checks and the first partial keepalive interval.
			start := time.Now().Add(time.Second)
			var previous [2]time.Time
			var intervals [2][]time.Duration
			for len(intervals[0]) < 3 || len(intervals[1]) < 3 {
				select {
				case request := <-requests:
					if request.at.Before(start) {
						continue
					}
					j := request.sender
					if !previous[j].IsZero() {
						interval := request.at.Sub(previous[j])
						if interval < minIntervals[j] || interval > maxIntervals[j] {
							t.Fatalf("isOffer=%t: keepalive interval %s, expected %s to %s",
								j == 0, interval, minIntervals[j], maxIntervals[j])
						}
						intervals[j] = append(intervals[j], interval)
					}
					previous[j] = request.at
				case <-ctx.Done():
					t.Fatalf("timed out waiting for keepalives: offer=%v answer=%v", intervals[0], intervals[1])
				}
			}
			t.Logf("keepalive intervals: offer=%v answer=%v", intervals[0], intervals[1])
		})
	}
}
