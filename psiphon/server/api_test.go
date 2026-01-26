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

package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func TestValidateAndGetProtobufBaseParams(t *testing.T) {

	params := make(common.APIParameters)

	params["session_id"] = prng.HexString(8)
	params["propagation_channel_id"] = strings.ToUpper(prng.HexString(8))
	params["sponsor_id"] = strings.ToUpper(prng.HexString(8))
	params["client_version"] = "1"
	params["client_platform"] = prng.HexString(8)
	params["client_features"] = []any{prng.HexString(8), prng.HexString(8)}
	params["client_build_rev"] = prng.HexString(8)
	params["device_region"] = "US"
	params["device_location"] = "gzzzz"
	params["egress_region"] = "US"
	params["network_type"] = prng.HexString(8)
	params["applied_tactics_tag"] = prng.HexString(8)

	packedParams, err := protocol.EncodePackedAPIParameters(params)
	if err != nil {
		t.Fatalf("protocol.EncodePackedAPIParameters failed: %v", err)
	}

	protoBaseParams, err := ValidateAndGetProtobufBaseParams(packedParams)
	if err != nil {
		t.Fatalf("ValidateAndGetProtobufBaseParams failed: %v", err)
	}

	if protoBaseParams.ClientAsn != nil ||
		protoBaseParams.ClientAso != nil ||
		protoBaseParams.ClientCity != nil ||
		protoBaseParams.ClientIsp != nil ||
		protoBaseParams.ClientRegion != nil ||
		protoBaseParams.LastConnected != nil ||
		protoBaseParams.AuthorizedAccessTypes != nil {

		t.Fatalf("unexpected non-nil field: %+v", protoBaseParams)
	}

	if *protoBaseParams.SessionId != params["session_id"].(string) ||
		*protoBaseParams.PropagationChannelId != params["propagation_channel_id"].(string) ||
		*protoBaseParams.SponsorId != params["sponsor_id"].(string) ||
		fmt.Sprintf("%+v", *protoBaseParams.ClientVersion) != fmt.Sprintf("%+v", params["client_version"]) ||
		*protoBaseParams.ClientPlatform != params["client_platform"].(string) ||
		fmt.Sprintf("%+v", protoBaseParams.ClientFeatures) != fmt.Sprintf("%+v", params["client_features"]) ||
		*protoBaseParams.ClientBuildRev != params["client_build_rev"].(string) ||
		*protoBaseParams.DeviceRegion != params["device_region"].(string) ||
		*protoBaseParams.DeviceLocation != params["device_location"].(string) ||
		*protoBaseParams.EgressRegion != params["egress_region"].(string) ||
		*protoBaseParams.NetworkType != params["network_type"].(string) ||
		*protoBaseParams.AppliedTacticsTag != params["applied_tactics_tag"].(string) {

		t.Fatalf("unexpected field: %+v", protoBaseParams)
	}
}
