// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fips140 is a stub replacing crypto/internal/fips140 for use
// outside the Go standard library. FIPS mode is always disabled.
package fips140

// Enabled reports whether FIPS 140 mode is active.
// Always false in this stub.
var Enabled bool

func RecordApproved()                  {}
func RecordNonApproved()               {}
func CAST(name string, f func() error) {}
func PCT(name string, f func() error)  {}
func ResetServiceIndicator()           {}
func ServiceIndicator() bool           { return false }
func Supported() error                 { return nil }
func Name() string                     { return "Go Cryptographic Module" }
func Version() string                  { return "latest" }
