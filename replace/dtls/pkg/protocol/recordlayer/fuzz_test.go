// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"testing"
)

func partialHeaderMismatch(a, b Header) bool {
	// Ignoring content length for now.
	a.ContentLen = b.ContentLen
	return a != b
}

func FuzzRecordLayer(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r RecordLayer
		if err := r.Unmarshal(data); err != nil {
			return
		}

		buf, err := r.Marshal()
		if err != nil {
			return
		}

		if len(buf) == 0 {
			t.Fatal("Zero buff")
		}

		var nr RecordLayer
		if err = nr.Unmarshal(data); err != nil {
			t.Fatal(err)
		}

		if partialHeaderMismatch(nr.Header, r.Header) {
			t.Fatalf("Header mismatch: %+v != %+v", nr.Header, r.Header)
		}
	})
}
