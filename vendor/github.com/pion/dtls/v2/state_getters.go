// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import "github.com/pion/dtls/v2/pkg/protocol/handshake"

// RemoteRandomBytes returns the random bytes from the client or server hello
func (s *State) RemoteRandomBytes() [handshake.RandomBytesLength]byte {
	return s.remoteRandom.RandomBytes
}
