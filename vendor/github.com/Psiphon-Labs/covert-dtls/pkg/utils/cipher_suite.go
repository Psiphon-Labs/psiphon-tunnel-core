package utils

import (
	"encoding/binary"
	"github.com/pion/dtls/v3"
)

func DecodeCipherSuiteIDs(buf []byte) ([]uint16, error) {
	if len(buf) < 2 {
		return nil, errBufferTooSmall
	}
	cipherSuitesCount := int(binary.BigEndian.Uint16(buf[0:])) / 2
	rtrn := make([]uint16, cipherSuitesCount)
	for i := 0; i < cipherSuitesCount; i++ {
		if len(buf) < (i*2 + 4) {
			return nil, errBufferTooSmall
		}

		rtrn[i] = binary.BigEndian.Uint16(buf[(i*2)+2:])
	}
	return rtrn, nil
}

func EncodeCipherSuiteIDs(cipherSuiteIDs []uint16) []byte {
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(cipherSuiteIDs)*2))
	for _, id := range cipherSuiteIDs {
		out = append(out, []byte{0x00, 0x00}...)
		binary.BigEndian.PutUint16(out[len(out)-2:], id)
	}
	return out
}

func DefaultCipherSuites() []dtls.CipherSuiteID {
	return []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		/*
			dtls.TLS_PSK_WITH_AES_128_CCM,
			dtls.TLS_PSK_WITH_AES_128_CCM_8,
			dtls.TLS_PSK_WITH_AES_256_CCM_8,
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
		*/
	}
}
