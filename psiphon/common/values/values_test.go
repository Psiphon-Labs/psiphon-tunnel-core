/*
 * Copyright (c) 2019, Psiphon Inc.
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

package values

import (
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

func TestValues(t *testing.T) {

	testValues := []string{"a", "b", "c"}

	spec := NewPickOneSpec(testValues)

	key, err := common.MakeSecureRandomBytes(32)
	if err != nil {
		t.Fatalf("MakeSecureRandomBytes failed: %s", err)
	}

	obfuscatedSpec, err := spec.Obfuscate(key, 10, 20)
	if err != nil {
		t.Fatalf("Obfuscate failed: %s", err)
	}

	spec = DeobfuscateValueSpec(obfuscatedSpec, key)
	if spec == nil {
		t.Fatalf("DeobfuscateValueSpec failed")
	}

	values := make(map[string]bool)

	SetUserAgentsSpec(spec)

	for i := 0; i < 100; i++ {
		values[GetUserAgent()] = true
	}

	if len(values) != len(testValues) {
		t.Fatalf("unexpected values count")
	}

	for _, testValue := range testValues {
		_, ok := values[testValue]
		if !ok {
			t.Fatalf("unexpected missing value")
		}
	}
}
