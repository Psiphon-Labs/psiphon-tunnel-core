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
)

func TestTunnelProtocolValidation(t *testing.T) {

	err := SupportedTunnelProtocols.Validate()
	if err != nil {
		t.Errorf("unexpected Validate error: %s", err)
	}

	invalidProtocols := TunnelProtocols{"OSSH", "INVALID-PROTOCOL"}
	err = invalidProtocols.Validate()
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

	if !reflect.DeepEqual(prunedProtocols, SupportedTunnelProtocols) {
		t.Errorf("unexpected %+v != %+v", prunedProtocols, SupportedTunnelProtocols)
	}
}

func TestTLSProfileValidation(t *testing.T) {

	err := SupportedTLSProfiles.Validate()
	if err != nil {
		t.Errorf("unexpected Validate error: %s", err)
	}

	invalidProfiles := TLSProfiles{"OSSH", "INVALID-PROTOCOL"}
	err = invalidProfiles.Validate()
	if err == nil {
		t.Errorf("unexpected Validate success")
	}

	pruneProfiles := make(TLSProfiles, 0)
	for i, p := range SupportedTLSProfiles {
		pruneProfiles = append(pruneProfiles, fmt.Sprintf("INVALID-PROFILE-%d", i))
		pruneProfiles = append(pruneProfiles, p)
	}
	pruneProfiles = append(pruneProfiles, fmt.Sprintf("INVALID-PROFILE-%d", len(SupportedTLSProfiles)))

	prunedProfiles := pruneProfiles.PruneInvalid()

	if !reflect.DeepEqual(prunedProfiles, SupportedTLSProfiles) {
		t.Errorf("unexpected %+v != %+v", prunedProfiles, SupportedTLSProfiles)
	}
}
