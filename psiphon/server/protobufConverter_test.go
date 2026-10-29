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
	"testing"

	pb "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/pb/psiphond"
)

// TestProtobufInproxyBrokerSelectionFields verifies that the in-proxy
// broker client selection metrics (which concurrent broker client a tunnel
// used, whether it replayed, and the acquisition wait) reach their protobuf
// messages. Population is by reflection
// over the generated struct's field names, so a field missing from the
// proto definition is dropped silently rather than failing; the JSON log
// path does not catch this, and the server integration tests check only
// the JSON fields.
func TestProtobufInproxyBrokerSelectionFields(t *testing.T) {

	// Handshake fields, logged with server_tunnel and failed_tunnel through
	// InproxyDialParams. Values are as emitted by getRequestLogFields:
	// bool for requestParamLogFlagAsBool, int for
	// requestParamLogStringAsInt.
	dialParams := protobufPopulateInproxyDialParams(LogFields{
		"inproxy_broker_is_replay":        true,
		"inproxy_broker_is_reuse":         true,
		"inproxy_broker_is_shared":        true,
		"inproxy_broker_candidate_number": 3,
		"inproxy_broker_acquire_wait_ms":  1250,
	})
	if !dialParams.GetInproxyBrokerIsShared() ||
		dialParams.GetInproxyBrokerCandidateNumber() != 3 ||
		dialParams.GetInproxyBrokerAcquireWaitMs() != 1250 {
		t.Fatalf("InproxyDialParams dropped broker selection fields: %+v", dialParams)
	}
	if !dialParams.GetInproxyBrokerIsReplay() || !dialParams.GetInproxyBrokerIsReuse() {
		t.Fatalf("InproxyDialParams dropped pre-existing broker fields: %+v", dialParams)
	}

	// Broker request fields, logged with inproxy_broker events, populated
	// as logFieldsToProtobuf does for that event.
	broker := &pb.InproxyBroker{}
	protobufPopulateMessage(LogFields{
		"event_name":                      "inproxy_broker",
		"inproxy_broker_is_replay":        true,
		"inproxy_broker_candidate_number": 2,
	}, broker, "inproxy_broker")
	if !broker.GetInproxyBrokerIsReplay() || broker.GetInproxyBrokerCandidateNumber() != 2 {
		t.Fatalf("InproxyBroker dropped broker selection fields: %+v", broker)
	}
}
