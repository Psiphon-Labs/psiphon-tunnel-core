// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This is the Go entry point for the libpsi app.
// It is invoked from Java.
//
// See README for details.
package main

import (
	"golang.org/x/mobile/app"

	_ "github.com/Psiphon-Labs/psiphon-tunnel-core/AndroidLibrary/go_psi"
	_ "golang.org/x/mobile/bind/java"
)

func main() {
	app.Run(app.Callbacks{})
}
