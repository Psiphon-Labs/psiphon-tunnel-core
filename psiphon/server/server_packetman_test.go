// +build PSIPHON_RUN_PACKET_MANIPULATOR_TEST

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

package server

import (
	"testing"
)

func TestServerPacketManipulation(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
			enableSSHAPIRequests: true,
			doHotReload:          false,
			doDefaultSponsorID:   false,
			denyTrafficRules:     false,
			requireAuthorization: true,
			omitAuthorization:    false,
			doTunneledWebRequest: true,
			doTunneledNTPRequest: true,
			forceFragmenting:     false,
			forceLivenessTest:    false,
			doPruneServerEntries: false,
			doDanglingTCPConn:    true,
			doPacketManipulation: true,
		})
}

func TestServerPacketManipulationReplay(t *testing.T) {
	runServerReplayTests(t, true)
}
