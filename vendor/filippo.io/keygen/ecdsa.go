package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"fmt"
	"io"
	"math/big"

	"filippo.io/bigmod"
	"golang.org/x/crypto/hkdf"
)

// ECDSA generates an ECDSA key deterministically from a random secret using a
// procedure equivalent to that in FIPS 186-5, Appendix A.2.2.
//
// The secret should be uniform, must be at least 128 bits long (ideally, 256
// bits long), and should not be reused for other purposes.
//
// The output MAY CHANGE until this package reaches v1.0.0.
func ECDSA(c elliptic.Curve, secret []byte) (*ecdsa.PrivateKey, error) {
	if len(secret) < 16 {
		return nil, fmt.Errorf("input secret must be at least 128 bits")
	}

	var salt string
	switch c {
	case elliptic.P256():
		salt = "ECDSA key generation: NIST P-256"
	case elliptic.P384():
		salt = "ECDSA key generation: NIST P-384"
	case elliptic.P521():
		salt = "ECDSA key generation: NIST P-521"
	default:
		return nil, fmt.Errorf("unsupported curve %s", c.Params().Name)
	}

	prk := hkdf.Extract(sha512.New, secret, []byte(salt))
	r := hkdf.Expand(sha512.New, prk, nil)

	N := bigmod.NewModulusFromBig(c.Params().N)

	b := make([]byte, N.Size())
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("HKDF error %v", err)
	}

	// Since P-521's order bitsize is not a multiple of 8, mask off the excess
	// bits to increase the chance of hitting a value in (0, N).
	if c == elliptic.P521() {
		b[0] &= 0b0000_0001
	}

	// FIPS 186-4 checks k <= N - 2 and then adds one. Checking 0 < k <= N - 1
	// is strictly equivalent but is more API-friendly, since SetBytes already
	// checks for overflows and doesn't require an addition.
	// (None of this matters anyway because the chance of selecting zero is
	// cryptographically negligible.)
	k := bigmod.NewNat()
	if _, err := k.SetBytes(b, N); err != nil || k.IsZero() == 1 {
		return ECDSA(c, prk)
	}

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = new(big.Int).SetBytes(k.Bytes(N))
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes(N))
	return priv, nil
}

// ECDSALegacy generates an ECDSA key deterministically from a random stream
// using the procedure given in FIPS 186-5, Appendix A.2.1, in a way compatible
// with Go 1.19.
//
// Note that ECDSALegacy may leak bits of the key through timing side-channels.
func ECDSALegacy(c elliptic.Curve, rand io.Reader) (*ecdsa.PrivateKey, error) {
	params := c.Params()
	// Note that for P-521 this will actually be 63 bits more than the order, as
	// division rounds down, but the extra bit is inconsequential and we want to
	// retain compatibility with Go 1.19 as was implemented.
	b := make([]byte, params.N.BitLen()/8+8)
	_, err := io.ReadFull(rand, b)
	if err != nil {
		return nil, err
	}

	one := big.NewInt(1)
	k := new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}
