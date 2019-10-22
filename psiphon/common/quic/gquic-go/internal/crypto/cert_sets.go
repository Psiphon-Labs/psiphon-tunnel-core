package crypto

import (
	"bytes"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic/gquic-go/quic-go-certificates"
)

type certSet [][]byte

var certSets = map[uint64]certSet{
	certsets.CertSet2Hash: certsets.CertSet2,
	certsets.CertSet3Hash: certsets.CertSet3,
}

// findCertInSet searches for the cert in the set. Negative return value means not found.
func (s *certSet) findCertInSet(cert []byte) int {
	for i, c := range *s {
		if bytes.Equal(c, cert) {
			return i
		}
	}
	return -1
}
