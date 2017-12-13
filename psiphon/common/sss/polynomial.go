package sss

import "io"

// the degree of the polynomial
func degree(p []byte) int {
	return len(p) - 1
}

// evaluate the polynomial at the given point
func eval(p []byte, x byte) (result byte) {
	// Horner's scheme
	for i := 1; i <= len(p); i++ {
		result = mul(result, x) ^ p[len(p)-i]
	}
	return
}

// generates a random n-degree polynomial w/ a given x-intercept
func generate(degree byte, x byte, rand io.Reader) ([]byte, error) {
	result := make([]byte, degree+1)
	result[0] = x

	buf := make([]byte, degree-1)
	if _, err := io.ReadFull(rand, buf); err != nil {
		return nil, err
	}

	for i := byte(1); i < degree; i++ {
		result[i] = buf[i-1]
	}

	// the Nth term can't be zero, or else it's a (N-1) degree polynomial
	for {
		buf = make([]byte, 1)
		if _, err := io.ReadFull(rand, buf); err != nil {
			return nil, err
		}

		if buf[0] != 0 {
			result[degree] = buf[0]
			return result, nil
		}
	}
}

// an input/output pair
type pair struct {
	x, y byte
}

// Lagrange interpolation
func interpolate(points []pair, x byte) (value byte) {
	for i, a := range points {
		weight := byte(1)
		for j, b := range points {
			if i != j {
				top := x ^ b.x
				bottom := a.x ^ b.x
				factor := div(top, bottom)
				weight = mul(weight, factor)
			}
		}
		value = value ^ mul(weight, a.y)
	}
	return
}
