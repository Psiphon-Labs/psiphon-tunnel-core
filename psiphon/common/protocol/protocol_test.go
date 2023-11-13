/*
 * Copyright (c) 2018, Psiphon Inc.
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

package protocol

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

func TestTunnelProtocolValidation(t *testing.T) {

	validSupportedProtocols := make(TunnelProtocols, 0)
	for _, p := range SupportedTunnelProtocols {
		if common.Contains(DisabledTunnelProtocols, p) {
			continue
		}
		validSupportedProtocols = append(validSupportedProtocols, p)
	}

	if len(validSupportedProtocols) == len(SupportedTunnelProtocols) {

		err := SupportedTunnelProtocols.Validate()
		if err != nil {
			t.Errorf("unexpected Validate error: %s", err)
		}

	} else {

		err := SupportedTunnelProtocols.Validate()
		if err == nil {
			t.Errorf("unexpected Validate success")
		}

		err = validSupportedProtocols.Validate()
		if err != nil {
			t.Errorf("unexpected Validate error: %s", err)
		}

	}

	invalidProtocols := TunnelProtocols{"OSSH", "INVALID-PROTOCOL"}
	err := invalidProtocols.Validate()
	if err == nil {
		t.Errorf("unexpected Validate success")
	}

	pruneProtocols := make(TunnelProtocols, 0)
	for i, p := range SupportedTunnelProtocols {
		pruneProtocols = append(pruneProtocols, fmt.Sprintf("INVALID-PROTOCOL-%d", i))
		pruneProtocols = append(pruneProtocols, p)
	}
	pruneProtocols = append(pruneProtocols, fmt.Sprintf("INVALID-PROTOCOL-%d", len(SupportedTunnelProtocols)))

	prunedProtocols := pruneProtocols.PruneInvalid()

	if !reflect.DeepEqual(prunedProtocols, validSupportedProtocols) {
		t.Errorf("unexpected %+v != %+v", prunedProtocols, validSupportedProtocols)
	}
}

func TestTLSProfileValidation(t *testing.T) {

	// Test: valid profiles

	err := SupportedTLSProfiles.Validate(nil)
	if err != nil {
		t.Errorf("unexpected Validate error: %s", err)
	}

	// Test: invalid profile

	profiles := TLSProfiles{TLS_PROFILE_RANDOMIZED, "INVALID-TLS-PROFILE"}
	err = profiles.Validate(nil)
	if err == nil {
		t.Errorf("unexpected Validate success")
	}

	// Test: valid custom profile

	customProfiles := []string{"CUSTOM-TLS-PROFILE"}

	profiles = TLSProfiles{TLS_PROFILE_RANDOMIZED, "CUSTOM-TLS-PROFILE"}
	err = profiles.Validate(customProfiles)
	if err != nil {
		t.Errorf("unexpected Validate error: %s", err)
	}

	// Test: prune invalid profiles

	pruneProfiles := make(TLSProfiles, 0)
	for i, p := range SupportedTLSProfiles {
		pruneProfiles = append(pruneProfiles, fmt.Sprintf("INVALID-PROFILE-%d", i))
		pruneProfiles = append(pruneProfiles, p)
	}
	pruneProfiles = append(pruneProfiles, fmt.Sprintf("INVALID-PROFILE-%d", len(SupportedTLSProfiles)))

	prunedProfiles := pruneProfiles.PruneInvalid(nil)

	if !reflect.DeepEqual(prunedProfiles, SupportedTLSProfiles) {
		t.Errorf("unexpected %+v != %+v", prunedProfiles, SupportedTLSProfiles)
	}

	// Test: don't prune valid custom profiles

	pruneProfiles = TLSProfiles{TLS_PROFILE_RANDOMIZED, "CUSTOM-TLS-PROFILE"}

	prunedProfiles = pruneProfiles.PruneInvalid(customProfiles)

	if !reflect.DeepEqual(prunedProfiles, pruneProfiles) {
		t.Errorf("unexpected %+v != %+v", prunedProfiles, pruneProfiles)
	}
}
