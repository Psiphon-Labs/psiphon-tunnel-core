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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package inproxy

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestBrokerClientResponseFlags verifies, for every broker API and every
// combination of NoMatch, Limited and MustUpgrade flags, that a decoded
// response invokes BrokerClientResponseReceived once with the original round
// tripper after transport success, that retryableNoMatch is true only for a
// ClientOffer with NoMatch and without Limited, and that malformed responses
// and ProxyAnswer produce no notification.
func TestBrokerClientResponseFlags(t *testing.T) {
	type responseFlags struct {
		NoMatch, Limited, MustUpgrade bool
	}
	type testCase struct {
		api       string
		flags     responseFlags
		malformed bool
	}
	var cases []testCase
	// Exercise precedence for every flag combination, including
	// overlapping flags such as MustUpgrade with NoMatch. Proxy NoMatch is
	// ordinary success.
	for _, api := range []string{"offer", "announce", "precheck"} {
		for bits := 0; bits < 8; bits++ {
			cases = append(cases, testCase{api: api, flags: responseFlags{
				NoMatch: bits&1 != 0, Limited: bits&2 != 0, MustUpgrade: bits&4 != 0,
			}})
		}
	}
	for _, api := range []string{"dsl", "relay", "answer"} {
		cases = append(cases, testCase{api: api})
	}
	for _, api := range []string{"offer", "announce", "precheck", "dsl", "relay", "answer"} {
		cases = append(cases, testCase{api: api, malformed: true})
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%+v/malformed=%v", tc.api, tc.flags, tc.malformed), func(t *testing.T) {
			var payload []byte
			var err error
			switch tc.api {
			case "offer":
				payload, err = MarshalClientOfferResponse(&ClientOfferResponse{
					NoMatch: tc.flags.NoMatch, Limited: tc.flags.Limited, MustUpgrade: tc.flags.MustUpgrade,
				})
			case "announce", "precheck":
				payload, err = MarshalProxyAnnounceResponse(&ProxyAnnounceResponse{
					NoMatch: tc.flags.NoMatch, Limited: tc.flags.Limited, MustUpgrade: tc.flags.MustUpgrade,
				})
			case "dsl":
				payload, err = MarshalClientDSLResponse(&ClientDSLResponse{})
			case "relay":
				payload, err = MarshalClientRelayedPacketResponse(&ClientRelayedPacketResponse{})
			case "answer":
				payload, err = MarshalProxyAnswerResponse(&ProxyAnswerResponse{})
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.malformed {
				payload = []byte("invalid response")
			}
			key, err := GenerateSessionPrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			publicKey, err := key.GetPublicKey()
			if err != nil {
				t.Fatal(err)
			}
			secret, err := GenerateRootObfuscationSecret()
			if err != nil {
				t.Fatal(err)
			}
			sessions, err := NewResponderSessions(key, secret, 0)
			if err != nil {
				t.Fatal(err)
			}
			rt := &proxyAcquisitionTestRoundTripper{sessions: sessions, handle: func([]byte) ([]byte, error) {
				return payload, nil
			}}
			transportSucceeded, callbacks := false, 0
			wantRetryableNoMatch := tc.api == "offer" && tc.flags.NoMatch && !tc.flags.Limited
			coordinator := &testBrokerDialCoordinator{
				brokerPublicKey: publicKey, brokerRootObfuscationSecret: secret, brokerClientRoundTripper: rt,
				brokerClientRoundTripperSucceeded: func(RoundTripper) { transportSucceeded = true },
				brokerClientRoundTripperFailed:    func(RoundTripper) { t.Error("unexpected transport failure") },
				brokerClientResponseReceived: func(gotRT RoundTripper, retryableNoMatch bool) {
					callbacks++
					if gotRT != rt || retryableNoMatch != wantRetryableNoMatch || !transportSucceeded {
						t.Errorf("incorrect callback identity/retryableNoMatch/order: retryableNoMatch=%v", retryableNoMatch)
					}
				},
			}
			client, err := NewBrokerClient(coordinator)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			switch tc.api {
			case "offer":
				_, err = client.ClientOffer(ctx, &ClientOfferRequest{}, false)
			case "announce", "precheck":
				_, err = client.ProxyAnnounce(ctx, 0, &ProxyAnnounceRequest{PreCheckTactics: tc.api == "precheck"})
			case "dsl":
				_, err = client.ClientDSL(ctx, &ClientDSLRequest{})
			case "relay":
				_, err = client.ClientRelayedPacket(ctx, &ClientRelayedPacketRequest{})
			case "answer":
				_, err = client.ProxyAnswer(ctx, &ProxyAnswerRequest{})
			}
			if (err != nil) != tc.malformed || !transportSucceeded {
				t.Fatalf("unexpected response error/transport outcome: %v", err)
			}
			wantCallbacks := 1
			if tc.malformed || tc.api == "answer" {
				wantCallbacks = 0
			}
			if callbacks != wantCallbacks {
				t.Fatalf("got %d callbacks, want %d", callbacks, wantCallbacks)
			}
		})
	}
}
