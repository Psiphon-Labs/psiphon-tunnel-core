// Package sss implements Shamir's Secret Sharing algorithm over GF(2^8).
//
// Shamir's Secret Sharing algorithm allows you to securely share a secret with
// N people, allowing the recovery of that secret if K of those people combine
// their shares.
//
// It begins by encoding a secret as a number (e.g., 42), and generating N
// random polynomial equations of degree K-1 which have an X-intercept equal to
// the secret. Given K=3, the following equations might be generated:
//
//     f1(x) =  78x^2 +  19x + 42
//     f2(x) = 128x^2 + 171x + 42
//     f3(x) = 121x^2 +   3x + 42
//     f4(x) =  91x^2 +  95x + 42
//     etc.
//
// These polynomials are then evaluated for values of X > 0:
//
//     f1(1) =  139
//     f2(2) =  896
//     f3(3) = 1140
//     f4(4) = 1783
//     etc.
//
// These (x, y) pairs are the shares given to the parties. In order to combine
// shares to recover the secret, these (x, y) pairs are used as the input points
// for Lagrange interpolation, which produces a polynomial which matches the
// given points. This polynomial can be evaluated for f(0), producing the secret
// value--the common x-intercept for all the generated polynomials.
//
// If fewer than K shares are combined, the interpolated polynomial will be
// wrong, and the result of f(0) will not be the secret.
//
// This package constructs polynomials over the field GF(2^8) for each byte of
// the secret, allowing for fast splitting and combining of anything which can
// be encoded as bytes.
//
// This package has not been audited by cryptography or security professionals.
package sss

import (
	"crypto/rand"
	"errors"
	"io"
)

var (
	// ErrInvalidCount is returned when the count parameter is invalid.
	ErrInvalidCount = errors.New("N must be >= K")
	// ErrInvalidThreshold is returned when the threshold parameter is invalid.
	ErrInvalidThreshold = errors.New("K must be > 1")
)

// Split the given secret into N shares of which K are required to recover the
// secret. Returns a map of share IDs (1-255) to shares.
func Split(n, k byte, secret []byte) (map[byte][]byte, error) {
	return split(n, k, secret, rand.Reader)
}

// SplitUsingReader splits the given secret, as Split does, but using the
// specified reader to create random polynomials. Use for deterministic
// splitting; caller must ensure reader is cryptographically secure.
func SplitUsingReader(
	n, k byte, secret []byte, reader io.Reader) (map[byte][]byte, error) {

	return split(n, k, secret, reader)
}

func split(n, k byte, secret []byte, randReader io.Reader) (map[byte][]byte, error) {
	if k <= 1 {
		return nil, ErrInvalidThreshold
	}

	if n < k {
		return nil, ErrInvalidCount
	}

	shares := make(map[byte][]byte, n)

	for _, b := range secret {
		p, err := generate(k-1, b, randReader)
		if err != nil {
			return nil, err
		}

		for x := byte(1); x <= n; x++ {
			shares[x] = append(shares[x], eval(p, x))
		}
	}

	return shares, nil
}

// Combine the given shares into the original secret.
//
// N.B.: There is no way to know whether the returned value is, in fact, the
// original secret.
func Combine(shares map[byte][]byte) []byte {
	var secret []byte
	for _, v := range shares {
		secret = make([]byte, len(v))
		break
	}

	points := make([]pair, len(shares))
	for i := range secret {
		p := 0
		for k, v := range shares {
			points[p] = pair{x: k, y: v[i]}
			p++
		}
		secret[i] = interpolate(points, 0)
	}

	return secret
}
