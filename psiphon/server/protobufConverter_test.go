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

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	pb "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/pb/psiphond"
)

// TestProtobufInproxyBrokerSelectionFields verifies that the in-proxy
// broker client selection metrics (which concurrent broker client a tunnel
// used and whether it replayed) reach their protobuf
// messages, for the client's handshake fields and the broker's own request
// log. Population is by reflection over the generated struct's
// field names, so a field missing from the proto definition is dropped
// silently rather than failing. The server integration tests catch the
// same omission only when built with PSIPHON_RUN_PROTOBUF_LOGGING_TEST and
// only for the fields their expected-field lists name.
func TestProtobufInproxyBrokerSelectionFields(t *testing.T) {

	// Handshake fields, logged with server_tunnel and failed_tunnel through
	// InproxyDialParams. Values are as emitted by getRequestLogFields:
	// bool for requestParamLogFlagAsBool, int for
	// requestParamLogStringAsInt.
	dialParams := protobufPopulateInproxyDialParams(LogFields{
		"inproxy_broker_is_replay":        true,
		"inproxy_broker_is_reuse":         true,
		"inproxy_broker_candidate_number": 3,
	})
	if dialParams.GetInproxyBrokerCandidateNumber() != 3 {
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

// TestInproxyBrokerTimingFields verifies that the in-proxy dial broker
// client acquire duration and the broker client transport and session
// durations survive packed encoding, pass inproxyDialParams validation, are
// logged as ints, and reach InproxyDialParams.
func TestInproxyBrokerTimingFields(t *testing.T) {
	params := common.APIParameters{
		"inproxy_dial_broker_client_acquire_duration": "5",
		"inproxy_broker_transport_dial_duration":      "12",
		"inproxy_broker_session_handshake_duration":   "34",
	}
	packed, err := protocol.EncodePackedAPIParameters(params)
	if err != nil {
		t.Fatal(err)
	}
	params, err = protocol.DecodePackedAPIParameters(packed)
	if err != nil {
		t.Fatal(err)
	}
	err = validateRequestParams(params, inproxyDialParams)
	if err != nil {
		t.Fatal(err)
	}
	logFields := getRequestLogFields(
		"", "", "", GeoIPData{}, nil, params, inproxyDialParams)
	if logFields["inproxy_dial_broker_client_acquire_duration"] != 5 ||
		logFields["inproxy_broker_transport_dial_duration"] != 12 ||
		logFields["inproxy_broker_session_handshake_duration"] != 34 {
		t.Fatalf("unexpected log fields: %v", logFields)
	}
	dialParams := protobufPopulateInproxyDialParams(logFields)
	if dialParams.GetInproxyDialBrokerClientAcquireDuration() != 5 ||
		dialParams.GetInproxyBrokerTransportDialDuration() != 12 ||
		dialParams.GetInproxyBrokerSessionHandshakeDuration() != 34 {
		t.Fatalf("InproxyDialParams dropped broker timing fields: %+v", dialParams)
	}
}

// TestInproxyBrokerReportSelectionMetrics verifies that report formatting
// omits proxy broker selection fields without altering the announcement
// metrics or the field list used for broker request logs.
func TestInproxyBrokerReportSelectionMetrics(t *testing.T) {
	params := common.APIParameters{
		"fronting_provider_id":            "A",
		"inproxy_broker_is_replay":        "1",
		"inproxy_broker_candidate_number": "7",
	}
	reportFormatter := getInproxyBrokerServerReportParameterLogFieldFormatter()
	for _, prefix := range []string{"", "inproxy_proxy_"} {
		report := reportFormatter(prefix, common.GeoIPData{}, params)
		for _, name := range []string{"inproxy_broker_is_replay", "inproxy_broker_candidate_number"} {
			if _, ok := report[prefix+name]; ok {
				t.Fatalf("unexpected broker selection field in report: %s", prefix+name)
			}
		}
		if report[prefix+"fronting_provider_id"] != "A" {
			t.Fatalf("report lost other proxy metrics: %v", report)
		}
	}
	broker := getInproxyBrokerAPIParameterLogFieldFormatter()("", common.GeoIPData{}, params)
	if broker["inproxy_broker_is_replay"] != true || broker["inproxy_broker_candidate_number"] != 7 {
		t.Fatalf("report formatting altered broker request metrics: %v", broker)
	}
	if params["inproxy_broker_is_replay"] != "1" || params["inproxy_broker_candidate_number"] != "7" {
		t.Fatal("report formatting mutated the original metrics")
	}
}
