/*
 * Copyright (c) 2018, Psiphon Inc.
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

package common

// APIParameters is a set of API parameter values, typically received
// from a Psiphon client and used/logged by the Psiphon server. The
// values are of varying types: strings, ints, arrays, structs, etc.
type APIParameters map[string]interface{}

// APIParameterValidator is a function that validates API parameters
// for a particular request or context.
type APIParameterValidator func(APIParameters) error

// GeoIPData is type-compatible with psiphon/server.GeoIPData.
type GeoIPData struct {
	Country        string
	City           string
	ISP            string
	ASN            string
	ASO            string
	DiscoveryValue int
}

// APIParameterLogFieldFormatter is a function that returns formatted
// LogFields containing the given GeoIPData and APIParameters.
type APIParameterLogFieldFormatter func(GeoIPData, APIParameters) LogFields
