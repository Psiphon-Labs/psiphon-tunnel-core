/*
 * Copyright (c) 2022, Psiphon Inc.
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
	"reflect"
	"strings"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func TestTransforms(t *testing.T) {
	err := runTestTransforms()
	if err != nil {
		t.Fatal(errors.Trace(err).Error())
	}
}

func runTestTransforms() error {

	transformNameAny := "exampleTransform1"
	transformNameScoped := "exampleTransform2"
	scopeName := "exampleScope"

	specs := Specs{
		transformNameAny: Spec{[2]string{"x", "y"}},
		transformNameScoped: Spec{
			[2]string{"aa", "cc"},
			[2]string{"bb", "(dd|ee)"},
			[2]string{"^([c0]{6})", "\\$\\{1\\}ff0"},
		},
	}

	scopedSpecs := ScopedSpecNames{
		SCOPE_ANY: []string{transformNameAny},
		scopeName: []string{transformNameScoped},
	}

	// Test: validation

	err := specs.Validate(false)
	if err != nil {
		return errors.Trace(err)
	}

	err = scopedSpecs.Validate(specs)
	if err != nil {
		return errors.Trace(err)
	}

	// Test: select based on scope

	name, spec := specs.Select(SCOPE_ANY, scopedSpecs)
	if name != transformNameAny || !reflect.DeepEqual(spec, specs[transformNameAny]) {
		return errors.TraceNew("unexpected select result")
	}

	name, spec = specs.Select(scopeName, scopedSpecs)
	if name != transformNameScoped || !reflect.DeepEqual(spec, specs[transformNameScoped]) {
		return errors.TraceNew("unexpected select result")
	}

	// Test: correct transform (assumes spec is transformNameScoped)

	seed, err := prng.NewSeed()
	if err != nil {
		return errors.Trace(err)
	}

	input := "aa0aa0aa0bb0aa0bb0aa0bb0aa0bb0aa0bb0aa0bb0aa0bb0aa0bb0aa0bb0aa"
	output, err := spec.ApplyString(seed, input)
	if err != nil {
		return errors.Trace(err)
	}

	if !strings.HasPrefix(output, "cc0cc0ff0") ||
		strings.IndexAny(output, "ab") != -1 ||
		strings.IndexAny(output, "de") == -1 {
		return errors.Tracef("unexpected apply result: %s", output)
	}

	// Test: same result with same seed

	previousOutput := output

	output, err = spec.ApplyString(seed, input)
	if err != nil {
		return errors.Trace(err)
	}

	if output != previousOutput {
		return errors.Tracef("unexpected different apply result")
	}

	// Test: different result with different seed (with high probability)

	different := false
	for i := 0; i < 1000; i++ {

		seed, err = prng.NewSeed()
		if err != nil {
			return errors.Trace(err)
		}

		output, err = spec.ApplyString(seed, input)
		if err != nil {
			return errors.Trace(err)
		}

		if output != previousOutput {
			different = true
			break
		}
	}

	if !different {
		return errors.Tracef("unexpected identical apply result")
	}

	return nil
}
