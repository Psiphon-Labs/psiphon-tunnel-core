// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"reflect"
	"testing"

	"github.com/pion/dtls/v2/pkg/crypto/hash"
	"github.com/pion/dtls/v2/pkg/crypto/signature"
)

func TestHandshakeMessageCertificateVerify(t *testing.T) {
	rawCertificateVerify := []byte{
		0x04, 0x03, 0x00, 0x47, 0x30, 0x45, 0x02, 0x20, 0x6b, 0x63, 0x17, 0xad, 0xbe, 0xb7, 0x7b, 0x0f,
		0x86, 0x73, 0x39, 0x1e, 0xba, 0xb3, 0x50, 0x9c, 0xce, 0x9c, 0xe4, 0x8b, 0xe5, 0x13, 0x07, 0x59,
		0x18, 0x1f, 0xe5, 0xa0, 0x2b, 0xca, 0xa6, 0xad, 0x02, 0x21, 0x00, 0xd3, 0xb5, 0x01, 0xbe, 0x87,
		0x6c, 0x04, 0xa1, 0xdc, 0x28, 0xaa, 0x5f, 0xf7, 0x1e, 0x9c, 0xc0, 0x1e, 0x00, 0x2c, 0xe5, 0x94,
		0xbb, 0x03, 0x0e, 0xf1, 0xcb, 0x28, 0x22, 0x33, 0x23, 0x88, 0xad,
	}
	parsedCertificateVerify := &MessageCertificateVerify{
		HashAlgorithm:      hash.Algorithm(rawCertificateVerify[0]),
		SignatureAlgorithm: signature.Algorithm(rawCertificateVerify[1]),
		Signature:          rawCertificateVerify[4:],
	}

	c := &MessageCertificateVerify{}
	if err := c.Unmarshal(rawCertificateVerify); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(c, parsedCertificateVerify) {
		t.Errorf("handshakeMessageCertificate unmarshal: got %#v, want %#v", c, parsedCertificateVerify)
	}

	raw, err := c.Marshal()
	if err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(raw, rawCertificateVerify) {
		t.Errorf("handshakeMessageCertificateVerify marshal: got %#v, want %#v", raw, rawCertificateVerify)
	}
}
