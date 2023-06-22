/*
Copyright 2014 Zachary Klippenstein

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

package regen

import (
	"bytes"
	"fmt"
	"math"
	"regexp/syntax"
)

// generatorFactory is a function that creates a random string generator from a regular expression AST.
type generatorFactory func(regexp *syntax.Regexp, args *GeneratorArgs) (*internalGenerator, error)

// Must be initialized in init() to avoid "initialization loop" compile error.
var generatorFactories map[syntax.Op]generatorFactory

const noBound = -1

func init() {
	generatorFactories = map[syntax.Op]generatorFactory{
		syntax.OpEmptyMatch:     opEmptyMatch,
		syntax.OpLiteral:        opLiteral,
		syntax.OpAnyCharNotNL:   opAnyCharNotNl,
		syntax.OpAnyChar:        opAnyChar,
		syntax.OpQuest:          opQuest,
		syntax.OpStar:           opStar,
		syntax.OpPlus:           opPlus,
		syntax.OpRepeat:         opRepeat,
		syntax.OpCharClass:      opCharClass,
		syntax.OpConcat:         opConcat,
		syntax.OpAlternate:      opAlternate,
		syntax.OpCapture:        opCapture,
		syntax.OpBeginLine:      noop,
		syntax.OpEndLine:        noop,
		syntax.OpBeginText:      noop,
		syntax.OpEndText:        noop,
		syntax.OpWordBoundary:   noop,
		syntax.OpNoWordBoundary: noop,
	}
}

type internalGenerator struct {
	Name         string
	GenerateFunc func() ([]byte, error)
}

func (gen *internalGenerator) Generate() (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panicked on bad input: Generate: %v", r)
		}
	}()
	return gen.GenerateFunc()
}

func (gen *internalGenerator) String() string {
	return gen.Name
}

// Create a new generator for each expression in regexps.
func newGenerators(regexps []*syntax.Regexp, args *GeneratorArgs) ([]*internalGenerator, error) {
	generators := make([]*internalGenerator, len(regexps))
	var err error

	// create a generator for each alternate pattern
	for i, subR := range regexps {
		generators[i], err = newGenerator(subR, args)
		if err != nil {
			return nil, err
		}
	}

	return generators, nil
}

// Create a new generator for r.
func newGenerator(regexp *syntax.Regexp, args *GeneratorArgs) (generator *internalGenerator, err error) {
	simplified := regexp.Simplify()

	factory, ok := generatorFactories[simplified.Op]
	if ok {
		return factory(simplified, args)
	}

	return nil, fmt.Errorf("invalid generator pattern: /%s/ as /%s/\n%s",
		regexp, simplified, inspectRegexpToString(simplified))
}

// Generator that does nothing.
func noop(regexp *syntax.Regexp, args *GeneratorArgs) (*internalGenerator, error) {
	return &internalGenerator{regexp.String(), func() ([]byte, error) {
		return []byte{}, nil
	}}, nil
}

func opEmptyMatch(regexp *syntax.Regexp, args *GeneratorArgs) (*internalGenerator, error) {
	enforceOp(regexp, syntax.OpEmptyMatch)
	return &internalGenerator{regexp.String(), func() ([]byte, error) {
		return []byte{}, nil
	}}, nil
}

func opLiteral(regexp *syntax.Regexp, args *GeneratorArgs) (*internalGenerator, error) {
	enforceOp(regexp, syntax.OpLiteral)
	return &internalGenerator{regexp.String(), func() ([]byte, error) {
		if args.ByteMode {
			return runesToBytes(regexp.Rune...)
		} else {
			return runesToUTF8(regexp.Rune...), nil
		}
	}}, nil
}

func opAnyChar(regexp *syntax.Regexp, args *GeneratorArgs) (*internalGenerator, error) {
	enforceOp(regexp, syntax.OpAnyChar)
	return &internalGenerator{regexp.String(), func() ([]byte, error) {
		if args.ByteMode {
			return runesToBytes(rune(args.rng.Intn(math.MaxUint8 + 1)))
		} else {
			return runesToUTF8(rune(args.rng.Int31())), nil
		}
	}}, nil
}

func opAnyCharNotNl(regexp *syntax.Regexp, args *GeneratorArgs) (*internalGenerator, error) {
	enforceOp(regexp, syntax.OpAnyCharNotNL)
	var charClass *tCharClass
	if args.ByteMode {
		charClass = newCharClass(0, rune(math.MaxUint8))
	} else {
		charClass = newCharClass(1, rune(math.MaxInt32))
	}
	return createCharClassGenerator(regexp.String(), charClass, args)
}

func opQuest(regexp *syntax.Regexp, args *GeneratorArgs) (*internalGenerator, error) {
	enforceOp(regexp, syntax.OpQuest)
	return createRepeatingGenerator(regexp, args, 0, 1)
}

func opStar(regexp *syntax.Regexp, args *GeneratorArgs) (*internalGenerator, error) {
	enforceOp(regexp, syntax.OpStar)
	return createRepeatingGenerator(regexp, args, noBound, noBound)
}

func opPlus(regexp *syntax.Regexp, args *GeneratorArgs) (*internalGenerator, error) {
	enforceOp(regexp, syntax.OpPlus)
	return createRepeatingGenerator(regexp, args, 1, noBound)
}

func opRepeat(regexp *syntax.Regexp, args *GeneratorArgs) (*internalGenerator, error) {
	enforceOp(regexp, syntax.OpRepeat)
	return createRepeatingGenerator(regexp, args, regexp.Min, regexp.Max)
}

// Handles syntax.ClassNL because the parser uses that flag to generate character
// classes that respect it.
func opCharClass(regexp *syntax.Regexp, args *GeneratorArgs) (*internalGenerator, error) {
	enforceOp(regexp, syntax.OpCharClass)
	var charClass *tCharClass
	if args.ByteMode {
		charClass = parseByteClass(regexp.Rune)
		if charClass == nil {
			return nil, fmt.Errorf("invalid byte class: /%s/", regexp)
		}
	} else {
		charClass = parseCharClass(regexp.Rune)
	}
	return createCharClassGenerator(regexp.String(), charClass, args)
}

func opConcat(regexp *syntax.Regexp, genArgs *GeneratorArgs) (*internalGenerator, error) {
	enforceOp(regexp, syntax.OpConcat)

	generators, err := newGenerators(regexp.Sub, genArgs)
	if err != nil {
		return nil, generatorError(err, "error creating generators for concat pattern /%s/", regexp)
	}

	return &internalGenerator{regexp.String(), func() ([]byte, error) {
		var result bytes.Buffer
		for _, generator := range generators {
			gen, err := generator.Generate()
			if err != nil {
				return nil, err
			}
			result.Write(gen)
		}
		return result.Bytes(), nil
	}}, nil
}

func opAlternate(regexp *syntax.Regexp, genArgs *GeneratorArgs) (*internalGenerator, error) {
	enforceOp(regexp, syntax.OpAlternate)

	generators, err := newGenerators(regexp.Sub, genArgs)
	if err != nil {
		return nil, generatorError(err, "error creating generators for alternate pattern /%s/", regexp)
	}

	numGens := len(generators)

	return &internalGenerator{regexp.String(), func() ([]byte, error) {
		i := genArgs.rng.Intn(numGens)
		generator := generators[i]
		return generator.Generate()
	}}, nil
}

func opCapture(regexp *syntax.Regexp, args *GeneratorArgs) (*internalGenerator, error) {
	enforceOp(regexp, syntax.OpCapture)

	if err := enforceSingleSub(regexp); err != nil {
		return nil, err
	}

	groupRegexp := regexp.Sub[0]
	generator, err := newGenerator(groupRegexp, args)
	if err != nil {
		return nil, err
	}

	// Group indices are 0-based, but index 0 is the whole expression.
	index := regexp.Cap - 1

	return &internalGenerator{regexp.String(), func() ([]byte, error) {
		return args.CaptureGroupHandler(index, regexp.Name, groupRegexp, generator, args)
	}}, nil
}

func defaultCaptureGroupHandler(index int, name string, group *syntax.Regexp, generator Generator, args *GeneratorArgs) ([]byte, error) {
	return generator.Generate()
}

// Panic if r.Op != op.
func enforceOp(r *syntax.Regexp, op syntax.Op) {
	if r.Op != op {
		panic(fmt.Sprintf("invalid Op: expected %s, was %s", opToString(op), opToString(r.Op)))
	}
}

// Return an error if r has 0 or more than 1 sub-expression.
func enforceSingleSub(regexp *syntax.Regexp) error {
	if len(regexp.Sub) != 1 {
		return generatorError(nil,
			"%s expected 1 sub-expression, but got %d: %s", opToString(regexp.Op), len(regexp.Sub), regexp)
	}
	return nil
}

func createCharClassGenerator(name string, charClass *tCharClass, args *GeneratorArgs) (*internalGenerator, error) {
	return &internalGenerator{name, func() ([]byte, error) {
		i := args.rng.Int31n(charClass.TotalSize)
		r := charClass.GetRuneAt(i)
		if args.ByteMode {
			return runesToBytes(r)
		} else {
			return runesToUTF8(r), nil
		}
	}}, nil
}

// Returns a generator that will run the generator for r's sub-expression [min, max] times.
func createRepeatingGenerator(regexp *syntax.Regexp, genArgs *GeneratorArgs, min, max int) (*internalGenerator, error) {
	if err := enforceSingleSub(regexp); err != nil {
		return nil, err
	}

	generator, err := newGenerator(regexp.Sub[0], genArgs)
	if err != nil {
		return nil, generatorError(err, "failed to create generator for subexpression: /%s/", regexp)
	}

	if min == noBound {
		min = int(genArgs.MinUnboundedRepeatCount)
	}
	if max == noBound {
		max = int(genArgs.MaxUnboundedRepeatCount)
	}

	return &internalGenerator{regexp.String(), func() ([]byte, error) {
		n := min + genArgs.rng.Intn(max-min+1)

		var result bytes.Buffer
		for i := 0; i < n; i++ {
			value, err := generator.Generate()
			if err != nil {
				return nil, err
			}
			result.Write(value)
		}
		return result.Bytes(), nil
	}}, nil
}
