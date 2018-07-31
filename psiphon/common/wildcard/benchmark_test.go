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

package wildcard

import (
	"testing"

	"github.com/gobwas/glob"
	go_glob "github.com/ryanuber/go-glob"
)

func BenchmarkFixedGlobPrecompile(b *testing.B) {
	g := glob.MustCompile(target)
	for i := 0; i < b.N; i++ {
		if !g.Match(target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkPrefixGlobPrecompile(b *testing.B) {
	g := glob.MustCompile("Lorem*")
	for i := 0; i < b.N; i++ {
		if !g.Match(target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkSuffixGlobPrecompile(b *testing.B) {
	g := glob.MustCompile("*aliqua.")
	for i := 0; i < b.N; i++ {
		if !g.Match(target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkMultipleGlobPrecompile(b *testing.B) {
	g := glob.MustCompile("*dolor*eiusmod*magna*")
	for i := 0; i < b.N; i++ {
		if !g.Match(target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkFixedGlob(b *testing.B) {
	for i := 0; i < b.N; i++ {
		g := glob.MustCompile(target)
		if !g.Match(target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkPrefixGlob(b *testing.B) {
	for i := 0; i < b.N; i++ {
		g := glob.MustCompile("Lorem*")
		if !g.Match(target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkSuffixGlob(b *testing.B) {
	for i := 0; i < b.N; i++ {
		g := glob.MustCompile("*aliqua.")
		if !g.Match(target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkMultipleGlob(b *testing.B) {
	for i := 0; i < b.N; i++ {
		g := glob.MustCompile("*dolor*eiusmod*magna*")
		if !g.Match(target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkFixedGoGlob(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !go_glob.Glob(target, target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkPrefixGoGlob(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !go_glob.Glob("Lorem*", target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkSuffixGoGlob(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !go_glob.Glob("*aliqua.", target) {
			b.Fatalf("unexpected result")
		}
	}
}

func BenchmarkMultipleGoGlob(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !go_glob.Glob("*dolor*eiusmod*magna*", target) {
			b.Fatalf("unexpected result")
		}
	}
}
