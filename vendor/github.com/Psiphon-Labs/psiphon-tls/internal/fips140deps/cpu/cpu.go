// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cpu replaces crypto/internal/fips140deps/cpu using
// golang.org/x/sys/cpu and runtime for architecture detection.
package cpu

import (
	"runtime"

	xcpu "golang.org/x/sys/cpu"
)

var (
	BigEndian = runtime.GOARCH == "mips" || runtime.GOARCH == "mips64" ||
		runtime.GOARCH == "ppc64" || runtime.GOARCH == "s390x"
	AMD64   = runtime.GOARCH == "amd64"
	ARM64   = runtime.GOARCH == "arm64"
	PPC64   = runtime.GOARCH == "ppc64"
	PPC64le = runtime.GOARCH == "ppc64le"
)

var (
	ARM64HasAES    = xcpu.ARM64.HasAES
	ARM64HasPMULL  = xcpu.ARM64.HasPMULL
	ARM64HasSHA2   = xcpu.ARM64.HasSHA2
	ARM64HasSHA512 = xcpu.ARM64.HasSHA512
	ARM64HasSHA3   = xcpu.ARM64.HasSHA3

	LOONG64HasLSX  bool // golang.org/x/sys/cpu may not have Loong64 support
	LOONG64HasLASX bool

	S390XHasAES    = xcpu.S390X.HasAES
	S390XHasAESCBC = xcpu.S390X.HasAESCBC
	S390XHasAESCTR = xcpu.S390X.HasAESCTR
	S390XHasAESGCM = xcpu.S390X.HasAESGCM
	S390XHasECDSA  bool // not available in golang.org/x/sys/cpu
	S390XHasGHASH  = xcpu.S390X.HasGHASH
	S390XHasSHA256 = xcpu.S390X.HasSHA256
	S390XHasSHA3   = xcpu.S390X.HasSHA3
	S390XHasSHA512 = xcpu.S390X.HasSHA512

	X86HasAES       = xcpu.X86.HasAES
	X86HasADX       = xcpu.X86.HasADX
	X86HasAVX       = xcpu.X86.HasAVX
	X86HasAVX2      = xcpu.X86.HasAVX2
	X86HasBMI2      = xcpu.X86.HasBMI2
	X86HasPCLMULQDQ = xcpu.X86.HasPCLMULQDQ
	X86HasSHA       bool // not available in golang.org/x/sys/cpu
	X86HasSSE41     = xcpu.X86.HasSSE41
	X86HasSSSE3     = xcpu.X86.HasSSSE3
)
