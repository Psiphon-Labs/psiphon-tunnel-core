//go:build !linux
// +build !linux

/*
 * Copyright (c) 2020, Psiphon Inc.
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

package packetman

import (
	std_errors "errors"
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

func IsSupported() bool {
	return false
}

var errUnsupported = std_errors.New("operation unsupported on this platform")

type Manipulator struct {
}

func NewManipulator(_ *Config) (*Manipulator, error) {
	return nil, errors.Trace(errUnsupported)
}

func (m *Manipulator) Start() error {
	return errors.Trace(errUnsupported)
}

func (m *Manipulator) Stop() {
}

func (m *Manipulator) SetSpecs(_ []*Spec) error {
	return errors.Trace(errUnsupported)
}

func (m *Manipulator) GetAppliedSpecName(
	_, _ *net.TCPAddr) (string, interface{}, error) {

	return "", nil, errors.Trace(errUnsupported)
}
