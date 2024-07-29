// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package elliptic

import "testing"

func TestString(t *testing.T) {
	tests := []struct {
		in  Curve
		out string
	}{
		{X25519, "X25519"},
		{P256, "P-256"},
		{P384, "P-384"},
		{0, "0x0"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.out, func(t *testing.T) {
			if tt.in.String() != tt.out {
				t.Fatalf("Expected: %s, got: %s", tt.out, tt.in.String())
			}
		})
	}
}
