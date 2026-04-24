// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package godebug is a lightweight replacement for crypto/internal/fips140deps/godebug.
// It reads settings from the GODEBUG environment variable at each call to Value.
// The real internal/godebug uses runtime linknames for cached updates; this
// implementation simply parses os.Getenv("GODEBUG") on demand, which is
// sufficient for the TLS package's needs.
package godebug

import "os"

// Setting represents a single GODEBUG setting.
type Setting struct {
	name string
}

// New returns a new Setting for the given name.
func New(name string) *Setting {
	return &Setting{name: name}
}

// Value returns the current value for this setting from the GODEBUG
// environment variable, or "" if the setting is not present.
func (s *Setting) Value() string {
	return lookupGodebug(s.name)
}

// IncNonDefault is a no-op. The real implementation increments a
// runtime/metrics counter; outside the stdlib we have no way to
// register those counters.
func (s *Setting) IncNonDefault() {}

// Value returns the current value for the named setting from the GODEBUG
// environment variable, or "" if the setting is not present.
func Value(name string) string {
	return lookupGodebug(name)
}

// lookupGodebug parses the GODEBUG environment variable (k=v,k2=v2,...)
// and returns the value for the given key, or "" if not found.
// If the key appears multiple times, the last occurrence wins.
func lookupGodebug(key string) string {
	// Strip leading # used for undocumented settings.
	if len(key) > 0 && key[0] == '#' {
		key = key[1:]
	}
	s := os.Getenv("GODEBUG")
	result := ""
	for len(s) > 0 {
		// Find end of this k=v item.
		end := len(s)
		for i := 0; i < len(s); i++ {
			if s[i] == ',' {
				end = i
				break
			}
		}
		item := s[:end]
		if end < len(s) {
			s = s[end+1:]
		} else {
			s = ""
		}
		// Split item on '='.
		eq := -1
		for i := 0; i < len(item); i++ {
			if item[i] == '=' {
				eq = i
				break
			}
		}
		if eq < 0 {
			continue
		}
		if item[:eq] == key {
			result = item[eq+1:]
		}
	}
	return result
}
