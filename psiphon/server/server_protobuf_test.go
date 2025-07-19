//go:build PSIPHON_RUN_PROTOBUF_LOGGING_TEST
// +build PSIPHON_RUN_PROTOBUF_LOGGING_TEST

/*
 * Copyright (c) 2025, Psiphon Inc.
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

func init() {
	// Building the tests with PSIPHON_RUN_PROTOBUF_LOGGING_TEST
	// globally switches the test run to protobuf logging mode.
	useProtobufLogging = true
}
