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

package parameters

import "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"

const LIVENESS_ANY = ""

// LivenessTestSpec specifies the parameters for a Liveness Test.
type LivenessTestSpec struct {
	MinUpstreamBytes   int
	MaxUpstreamBytes   int
	MinDownstreamBytes int
	MaxDownstreamBytes int
}

// LivenessTestSpecs is a map of tunnel protocol patterns to Liveness Test spec.
// Patterns may contain the '*' wildcard.
type LivenessTestSpecs map[string]*LivenessTestSpec

func (l LivenessTestSpecs) Validate() error {
	// Check that there is a LIVENESS_ANY entry.
	if _, ok := l[LIVENESS_ANY]; !ok {
		return errors.TraceNew("missing LIVENESS_ANY entry")
	}
	// Check that all entries are well-formed.
	for _, spec := range l {
		if spec.MinUpstreamBytes < 0 {
			return errors.TraceNew("invalid MinUpstreamBytes")
		}
		if spec.MaxUpstreamBytes < 0 {
			return errors.TraceNew("invalid MaxUpstreamBytes")
		}
		if spec.MinDownstreamBytes < 0 {
			return errors.TraceNew("invalid MinDownstreamBytes")
		}
		if spec.MaxDownstreamBytes < 0 {
			return errors.TraceNew("invalid MaxDownstreamBytes")
		}
	}
	return nil
}
