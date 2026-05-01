// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package constanttime

// Select returns x if v == 1 and y if v == 0.
// Its behavior is undefined if v takes any other value.
func Select(v, x, y int) int {
	v = int(boolToUint8(v != 0))
	return ^(v-1)&x | (v-1)&y
}

// ByteEq returns 1 if x == y and 0 otherwise.
func ByteEq(x, y uint8) int {
	return int(boolToUint8(x == y))
}

// Eq returns 1 if x == y and 0 otherwise.
func Eq(x, y int32) int {
	return int(boolToUint8(x == y))
}

// LessOrEq returns 1 if x <= y and 0 otherwise.
// Its behavior is undefined if x or y are negative or > 2**31 - 1.
func LessOrEq(x, y int) int {
	return int(boolToUint8(x <= y))
}

// boolToUint8 replaces the compiler intrinsic with a portable implementation.
func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
