/*
 * Copyright (c) 2022, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package parameters

import (
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// LabeledCIDRs consists of lists of CIDRs referenced by a label value.
type LabeledCIDRs map[string][]string

// Validate checks that the CIDR values are well-formed.
func (c LabeledCIDRs) Validate() error {
	for _, CIDRs := range c {
		for _, CIDR := range CIDRs {
			_, _, err := net.ParseCIDR(CIDR)
			if err != nil {
				return errors.Trace(err)
			}
		}
	}
	return nil
}
