// Copyright (c) The M1CPU Authors
// SPDX-License-Identifier: MPL-2.0

package m1cpu

import "fmt"

// generation returns the chip generation from a model name such as
// "Apple M4 Pro", or 0 when the name carries no generation.
func generation(model string) int {
	var gen int
	// If this errors, fallback to default int value
	if _, err := fmt.Sscanf(model, "Apple M%d", &gen); err != nil {
		return 0
	}
	return gen
}
