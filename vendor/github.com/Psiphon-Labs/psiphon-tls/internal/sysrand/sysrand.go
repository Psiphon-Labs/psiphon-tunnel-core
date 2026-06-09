// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sysrand is a stub replacing crypto/internal/sysrand.
// It delegates to crypto/rand for random byte generation.
package sysrand

import "crypto/rand"

func Read(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("sysrand: " + err.Error())
	}
}
