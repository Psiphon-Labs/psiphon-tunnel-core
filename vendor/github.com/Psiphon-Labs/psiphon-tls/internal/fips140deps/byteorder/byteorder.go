// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package byteorder replaces internal/byteorder using encoding/binary.
package byteorder

import "encoding/binary"

func LEUint16(b []byte) uint16 {
	return binary.LittleEndian.Uint16(b)
}

func BEUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func BEUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

func BEUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

func LEUint32(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}

func LEUint64(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}

func BEPutUint16(b []byte, v uint16) {
	binary.BigEndian.PutUint16(b, v)
}

func BEPutUint32(b []byte, v uint32) {
	binary.BigEndian.PutUint32(b, v)
}

func BEPutUint64(b []byte, v uint64) {
	binary.BigEndian.PutUint64(b, v)
}

func LEPutUint16(b []byte, v uint16) {
	binary.LittleEndian.PutUint16(b, v)
}

func LEPutUint32(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
}

func LEPutUint64(b []byte, v uint64) {
	binary.LittleEndian.PutUint64(b, v)
}

func BEAppendUint16(b []byte, v uint16) []byte {
	return binary.BigEndian.AppendUint16(b, v)
}

func BEAppendUint32(b []byte, v uint32) []byte {
	return binary.BigEndian.AppendUint32(b, v)
}

func BEAppendUint64(b []byte, v uint64) []byte {
	return binary.BigEndian.AppendUint64(b, v)
}

func LEAppendUint16(b []byte, v uint16) []byte {
	return binary.LittleEndian.AppendUint16(b, v)
}

func LEAppendUint32(b []byte, v uint32) []byte {
	return binary.LittleEndian.AppendUint32(b, v)
}

func LEAppendUint64(b []byte, v uint64) []byte {
	return binary.LittleEndian.AppendUint64(b, v)
}
