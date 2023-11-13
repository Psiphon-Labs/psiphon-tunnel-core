/*
 * Copyright (c) 2023, Psiphon Inc.
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
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

func getNetworkBytesTransferred() (int64, int64, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, errors.Trace(err)
	}

	defer file.Close()

	var totalNetworkBytesReceived, totalNetworkBytesSent int64
	scanner := bufio.NewScanner(file)

	// Parsing based on the formats used by dev_seq_show and dev_seq_printf_stats:
	// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/core/net-procfs.c#n105

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		// Skip header lines, loopback interface and tunnel interface
		if len(fields) < 17 || fields[0] == "Inter-|" || fields[0] == "face" ||
			strings.HasPrefix(fields[0], "lo") || strings.HasPrefix(fields[0], "tun") ||
			strings.HasPrefix(fields[0], "ipsec") || strings.HasPrefix(fields[0], "ppp") {
			continue
		}

		// Parse received bytes
		receivedNetworkBytes, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, 0, errors.Trace(err)
		}

		// Parse sent bytes
		sentNetworkBytes, err := strconv.ParseInt(fields[9], 10, 64)
		if err != nil {
			return 0, 0, errors.Trace(err)
		}

		totalNetworkBytesReceived += receivedNetworkBytes
		totalNetworkBytesSent += sentNetworkBytes
	}

	if scanner.Err() != nil {
		return 0, 0, errors.Trace(scanner.Err())
	}

	return totalNetworkBytesReceived, totalNetworkBytesSent, nil
}
