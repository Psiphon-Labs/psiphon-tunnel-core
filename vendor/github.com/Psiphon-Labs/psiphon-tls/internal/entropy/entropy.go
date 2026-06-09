// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package entropy is a stub replacing crypto/internal/entropy.
// It provides entropy using crypto/rand.
package entropy

import "crypto/rand"

type ScratchBuffer [1 << 25]byte

func Seed(memory *ScratchBuffer) ([48]byte, error) {
	var seed [48]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return seed, err
	}
	return seed, nil
}
