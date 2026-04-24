// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"encoding/binary"

	"github.com/pion/rtp"
)

/*
RFC 9335: Completely Encrypting RTP Header Extensions and Contributing Sources

Section 6.2. Encryption Procedure

When this mechanism [Cryptex] is active, the SRTP packet is protected as follows:

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
  |V=2|P|X|  CC   |M|     PT      |       sequence number         | |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
  |                           timestamp                           | |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
  |           synchronization source (SSRC) identifier            | |
+>+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
| |            contributing source (CSRC) identifiers             | |
| |                               ....                            | |
+>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
X |  0xC0 or 0xC2 |    0xDE       |           length              | |
+>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
| |                  RFC 8285 header extensions                   | |
| +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
| |                          payload  ...                         | |
| |                               +-------------------------------+ |
| |                               | RTP padding   | RTP pad count | |
+>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
| ~          SRTP Master Key Identifier (MKI) (OPTIONAL)          ~ |
| +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
| :                 authentication tag (RECOMMENDED)              : |
| +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
|                                                                   |
+- Encrypted Portion                       Authenticated Portion ---+
Figure 1: A Protected SRTP Packet
Note that, as required by [RFC8285], the 4 bytes at the start of the extension block are not encrypted.

Specifically, the Encrypted Portion MUST include any CSRC identifiers, any RTP header extension
(except for the first 4 bytes), and the RTP payload.
*/

const (
	minSrtpHeaderSize   = 12 // Minimum size of the SRTP header (12 bytes for RTP header without CSRCs and extensions)
	extensionHeaderSize = 4  // Size of the header extension (4 bytes for profile and length fields)
)

func isCryptexPacket(header *rtp.Header) bool {
	return header.Extension &&
		(header.ExtensionProfile == rtp.CryptexProfileOneByte || header.ExtensionProfile == rtp.CryptexProfileTwoByte)
}

func moveHeaderExtensionBeforeCSRCs(header *rtp.Header, buf []byte) {
	if len(header.CSRC) == 0 || !header.Extension {
		return
	}

	var tmp [extensionHeaderSize]byte
	csrcLen := len(header.CSRC) * 4
	copy(tmp[:], buf[minSrtpHeaderSize+csrcLen:minSrtpHeaderSize+csrcLen+extensionHeaderSize])
	copy(buf[minSrtpHeaderSize+extensionHeaderSize:], buf[minSrtpHeaderSize:minSrtpHeaderSize+csrcLen])
	copy(buf[minSrtpHeaderSize:], tmp[:])
}

func moveCSRCsBeforeHeaderExtension(header *rtp.Header, buf []byte) {
	if len(header.CSRC) == 0 || !header.Extension {
		return
	}

	var tmp [extensionHeaderSize]byte
	csrcLen := len(header.CSRC) * 4
	copy(tmp[:], buf[minSrtpHeaderSize:minSrtpHeaderSize+extensionHeaderSize])
	copy(buf[minSrtpHeaderSize:],
		buf[minSrtpHeaderSize+extensionHeaderSize:minSrtpHeaderSize+csrcLen+extensionHeaderSize])
	copy(buf[minSrtpHeaderSize+csrcLen:], tmp[:])
}

func encryptCryptexRTP(dst, plaintext []byte, sameBuffer bool, header *rtp.Header,
	encrypt func(dst, plaintext []byte, headerLen int) error,
) error {
	moveHeaderExtensionBeforeCSRCs(header, plaintext)

	// Update Header Extension Profile to Cryptex one
	if header.ExtensionProfile == rtp.ExtensionProfileOneByte {
		binary.BigEndian.PutUint16(plaintext[minSrtpHeaderSize:], rtp.CryptexProfileOneByte)
	} else {
		binary.BigEndian.PutUint16(plaintext[minSrtpHeaderSize:], rtp.CryptexProfileTwoByte)
	}

	err := encrypt(dst, plaintext, minSrtpHeaderSize+extensionHeaderSize)
	if err != nil {
		binary.BigEndian.PutUint16(plaintext[minSrtpHeaderSize:], header.ExtensionProfile)
		moveCSRCsBeforeHeaderExtension(header, plaintext)

		return err
	}

	if !sameBuffer {
		copy(dst, plaintext[:minSrtpHeaderSize+extensionHeaderSize])
		binary.BigEndian.PutUint16(plaintext[minSrtpHeaderSize:], header.ExtensionProfile)
		moveCSRCsBeforeHeaderExtension(header, plaintext)
	}
	moveCSRCsBeforeHeaderExtension(header, dst)

	return nil
}

func decryptCryptexRTP(dst, ciphertext []byte, sameBuffer bool, header *rtp.Header, headerLen int,
	decrypt func(dst, ciphertext []byte, headerLen int) error,
) error {
	moveHeaderExtensionBeforeCSRCs(header, ciphertext)
	err := decrypt(dst, ciphertext, minSrtpHeaderSize+extensionHeaderSize)
	if err != nil {
		moveCSRCsBeforeHeaderExtension(header, ciphertext)

		return err
	}

	if !sameBuffer {
		copy(dst, ciphertext[:minSrtpHeaderSize+extensionHeaderSize])
		moveCSRCsBeforeHeaderExtension(header, dst)
	}
	moveCSRCsBeforeHeaderExtension(header, ciphertext)

	// Update Header Extension Profile
	offset := minSrtpHeaderSize + len(header.CSRC)*4
	if header.ExtensionProfile == rtp.CryptexProfileOneByte {
		binary.BigEndian.PutUint16(dst[offset:], rtp.ExtensionProfileOneByte)
	} else {
		binary.BigEndian.PutUint16(dst[offset:], rtp.ExtensionProfileTwoByte)
	}

	// Unmarshal decrypted header extension.
	n, err := header.Unmarshal(dst)
	if err != nil {
		return err
	}
	if n != headerLen {
		return errHeaderLengthMismatch
	}

	return nil
}

// RFC 9335, section 5.1: If the packet contains CSRCs but no header extensions, an empty extension block
// consisting of the 0xC0DE tag and a 16-bit length field set to zero (explicitly permitted by [RFC3550])
// MUST be appended, and the X bit MUST be set to 1 to indicate an extension block is present.

func needsEmptyExtensionHeader(useCryptex bool, header *rtp.Header) bool {
	return useCryptex && len(header.CSRC) > 0 && !header.Extension
}

// insertEmptyExtensionHeader inserts an empty extension header into the RTP packet. It assumes that the dst is big
// enough to hold extra data.
func insertEmptyExtensionHeader(dst, plaintext []byte, sameBuffer bool, header *rtp.Header) []byte {
	header.Extension = true
	header.ExtensionProfile = rtp.ExtensionProfileOneByte
	header.Extensions = nil

	var emptyExtHdr [extensionHeaderSize]byte
	binary.BigEndian.PutUint16(emptyExtHdr[:], rtp.ExtensionProfileOneByte)

	offset := minSrtpHeaderSize + len(header.CSRC)*4
	plaintextLen := len(plaintext)
	if sameBuffer {
		plaintext = plaintext[:plaintextLen+extensionHeaderSize]
		copy(plaintext[offset+extensionHeaderSize:], plaintext[offset:plaintextLen])
		copy(plaintext[offset:], emptyExtHdr[:])
	} else {
		newPlaintext := dst[:plaintextLen+extensionHeaderSize]
		copy(newPlaintext, plaintext[:offset])
		copy(newPlaintext[offset:], emptyExtHdr[:])
		copy(newPlaintext[offset+extensionHeaderSize:], plaintext[offset:plaintextLen])
		plaintext = newPlaintext
	}

	plaintext[0] |= 0x10 // Set the X bit to indicate an extension block is present

	return plaintext
}
