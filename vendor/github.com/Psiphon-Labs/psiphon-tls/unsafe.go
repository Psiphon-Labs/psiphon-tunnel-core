// unsafe.go is based on qtls/unsafe.go
// https://github.com/quic-go/qtls-go1-20/blob/49f389c17d984e5b248f0a57cbae10dd4198a3bf/unsafe.go
/* Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package tls

import (
	"crypto/tls"
	"reflect"
	"unsafe"
)

func init() {
	if !structsEqual(&tls.ConnectionState{}, &ConnectionState{}) {
		panic("tls.ConnectionState doesn't match")
	}
}

func UnsafeFromConnectionState(ss *ConnectionState) *tls.ConnectionState {
	return (*tls.ConnectionState)(unsafe.Pointer(ss))
}

func structsEqual(a, b interface{}) bool {
	return compare(reflect.TypeOf(a), reflect.TypeOf(b))
}

// compare compares two types and returns true if and only if
// they can be casted to each other safely.
// compare does not currently support Maps, Chan, UnsafePointer if reflect.DeepEqual fails.
// Support for these types can be added if needed.
// note that field names are still compared.
func compare(a, b reflect.Type) bool {

	if reflect.DeepEqual(a, b) {
		return true
	}

	if a.Kind() != b.Kind() {
		return false
	}

	if a.Kind() == reflect.Pointer || a.Kind() == reflect.Slice {
		return compare(a.Elem(), b.Elem())
	}

	if a.Kind() == reflect.Func {
		if a.NumIn() != b.NumIn() || a.NumOut() != b.NumOut() {
			return false
		}
		for i_in := 0; i_in < a.NumIn(); i_in++ {
			if !compare(a.In(i_in), b.In(i_in)) {
				return false
			}
		}
		for i_out := 0; i_out < a.NumOut(); i_out++ {
			if !compare(a.Out(i_out), b.Out(i_out)) {
				return false
			}
		}
		return true
	}

	if a.Kind() == reflect.Struct {

		if a.NumField() != b.NumField() {
			return false
		}

		for i := 0; i < a.NumField(); i++ {
			fa := a.Field(i)
			fb := b.Field(i)

			if !reflect.DeepEqual(fa.Index, fb.Index) || fa.Name != fb.Name ||
				fa.Anonymous != fb.Anonymous || fa.Offset != fb.Offset {
				return false
			}

			if !reflect.DeepEqual(fa.Type, fb.Type) {
				if !compare(fa.Type, fb.Type) {
					return false
				}
			}
		}

		return true
	}

	// TODO: add support for missing types
	return false
}
