// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fips140tls is a stub replacing crypto/tls/internal/fips140tls.
// FIPS mode is always disabled.
package fips140tls

func Force()              {}
func Required() bool      { return false }
func TestingOnlyAbandon() {}
