// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

// This file exposes the package-internal, libSystem-backed ioctlPtr so that callers
// can issue ioctls that have no dedicated typed wrapper (e.g. SIOCGIFDELEGATE)
// without falling back to syscall.Syscall, which makes a direct SVC kernel
// trap.

package unix

import "unsafe"

// [Psiphon]
// IoctlPointer performs an ioctl on fd with request req and an arbitrary
// pointer argument, routed through libSystem.
func IoctlPointer(fd int, req uint, arg unsafe.Pointer) error {
	return ioctlPtr(fd, req, arg)
}
