// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"
)

func FuzzDtlsHandshake(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		h := &Handshake{}
		if err := h.Unmarshal(data); err != nil {
			return
		}
		buf, err := h.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if len(buf) == 0 {
			t.Fatal("Zero buff")
		}
	})
}
