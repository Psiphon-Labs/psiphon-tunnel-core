/*
 * Copyright (c) 2026, Psiphon Inc.
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

package server

import (
	"fmt"
	"testing"
)

func TestLoadConfigPacketTunnelExcludedIPv4Subnets(t *testing.T) {

	load := func(subnets string) (*Config, error) {
		return LoadConfig([]byte(fmt.Sprintf(
			`{"ServerIPAddress": "192.0.2.1", "PacketTunnelExcludedIPv4Subnets": %s}`,
			subnets)))
	}

	config, err := load(`["10.20.0.0/16", "10.40.5.6/16"]`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	got := fmt.Sprint(config.packetTunnelExcludedIPv4Subnets)
	if want := "[10.20.0.0/16 10.40.0.0/16]"; got != want {
		t.Errorf("subnets: got %s, want %s", got, want)
	}

	for _, invalid := range []string{`["10.20.0.0"]`, `["fd00::/8"]`, `["::ffff:10.1.0.0/112"]`,
		`["not-a-subnet"]`, `["192.168.1.0/24"]`, `["10.0.0.0/8"]`, `["0.0.0.0/0"]`,
		`["10.0.0.0/24"]`} {
		if _, err := load(invalid); err == nil {
			t.Errorf("LoadConfig accepted %s", invalid)
		}
	}
}
