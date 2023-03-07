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

package transforms

import (
	"encoding/hex"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

type ObfuscatorSeedTransformerParameters struct {
	TransformName string
	TransformSpec Spec
	TransformSeed *prng.Seed
}

// Apply applies the transformation in-place to the given slice of bytes.
// No change is made if the tranformation fails.
func (t *ObfuscatorSeedTransformerParameters) Apply(b []byte) error {
	if t.TransformSpec == nil {
		return nil
	}

	input := hex.EncodeToString(b)
	newSeedString, err := t.TransformSpec.ApplyString(t.TransformSeed, input)

	if err != nil {
		return errors.Trace(err)
	}

	newSeed, err := hex.DecodeString(newSeedString)
	if err != nil {
		return errors.Trace(err)
	}

	if len(newSeed) != len(b) {
		return errors.TraceNew("invalid transform spec")
	}

	copy(b, newSeed)

	return nil
}
