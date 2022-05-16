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

// Package transforms provides a mechanism to define and apply string data
// transformations, with the transformations defined by regular expressions
// to match data to be transformed, and regular expression generators to
// specify additional or replacement data.
package transforms

import (
	"regexp"
	"regexp/syntax"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	regen "github.com/zach-klippenstein/goregen"
)

const (
	SCOPE_ANY = ""
)

// Spec is a transform spec. A spec is a list of individual transforms to be
// applied in order. Each transform is defined by two elements: a regular
// expression to by matched against the input; and a regular expression
// generator which generates new data. Subgroups from the regular expression
// may be specified in the regular expression generator, and are populated
// with the subgroup match, and in this way parts of the original matching
// data may be retained in the transformed data.
//
// For example, with the transform [2]string{"([a-b])", "\\$\\
// {1\\}"c}, substrings consisting of the characters 'a' and 'b' will be
// transformed into the same substring with a single character 'c' appended.
type Spec [][2]string

// Specs is a set of named Specs.
type Specs map[string]Spec

// Validate checks that all entries in a set of Specs is well-formed, with
// valid regular expressions.
func (specs Specs) Validate() error {
	seed, err := prng.NewSeed()
	if err != nil {
		return errors.Trace(err)
	}
	for _, spec := range specs {
		// Call Apply to compile/validate the regular expressions and generators.
		_, err := spec.Apply(seed, "")
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

// ScopedSpecNames defines groups a list of Specs, referenced by their Spec
// name, with the group defined by a scope. The meaning of scope depends on
// the context in which the transforms are to be used.
//
// For example, in the context of DNS request transforms, the scope is the DNS
// server for which a specific group of transforms is known to be effective.
//
// The scope name "" is SCOPE_ANY, and matches any input scope name when there
// is no specific entry for that scope name in ScopedSpecNames.
type ScopedSpecNames map[string][]string

// Validate checks that the ScopedSpecNames is well-formed and referenced Spec
// names are defined in the corresponding input specs.
func (scopedSpecs ScopedSpecNames) Validate(specs Specs) error {

	for _, scoped := range scopedSpecs {
		for _, specName := range scoped {
			_, ok := specs[specName]
			if !ok {
				return errors.Tracef("undefined spec name: %s", specName)
			}
		}
	}

	return nil
}

// Select picks a Spec from Specs based on the input scope and scoping rules.
// If the input scope name is defined in scopedSpecs, that match takes
// precedence. Otherwise SCOPE_ANY is selected, when present.
//
// After the scope is resolved, Select randomly selects from the matching Spec
// list.
//
// Select will return "", nil when no selection can be made.
func (specs Specs) Select(scope string, scopedSpecs ScopedSpecNames) (string, Spec) {

	if scope != SCOPE_ANY {
		scoped, ok := scopedSpecs[scope]
		if ok {
			// If the specific scope is defined but empty, this means select
			// nothing -- don't fall through to SCOPE_ANY.
			if len(scoped) == 0 {
				return "", nil
			}

			specName := scoped[prng.Intn(len(scoped))]
			spec, ok := specs[specName]
			if !ok {
				// specName is not found in specs, which should not happen if
				// Validate passes; select nothing in this case.
				return "", nil
			}
			return specName, spec
		}
		// Fall through to SCOPE_ANY.
	}

	anyScope, ok := scopedSpecs[SCOPE_ANY]
	if !ok || len(anyScope) == 0 {
		// No SCOPE_ANY, or SCOPE_ANY is an empty list.
		return "", nil
	}

	specName := anyScope[prng.Intn(len(anyScope))]
	spec, ok := specs[specName]
	if !ok {
		return "", nil
	}
	return specName, spec
}

// Apply applies the Spec to the input string, producting the output string.
//
// The input seed is used for all random generation. The same seed can be
// supplied to produce the same output, for replay.
func (spec Spec) Apply(seed *prng.Seed, input string) (string, error) {

	// TODO: complied regexp and regen could be cached, but the seed is an
	// issue with the regen.

	value := input
	for _, transform := range spec {

		args := &regen.GeneratorArgs{
			RngSource: prng.NewPRNGWithSeed(seed),
			Flags:     syntax.OneLine | syntax.NonGreedy,
		}
		rg, err := regen.NewGenerator(transform[1], args)
		if err != nil {
			panic(err.Error())
		}
		replacement := rg.Generate()
		if err != nil {
			panic(err.Error())
		}

		re := regexp.MustCompile(transform[0])
		value = re.ReplaceAllString(value, replacement)
	}
	return value, nil
}
