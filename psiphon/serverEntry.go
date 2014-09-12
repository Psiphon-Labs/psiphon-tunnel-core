/*
 * Copyright (c) 2014, Psiphon Inc.
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

package psiphon

// ServerEntry represents a Psiphon server. It contains information
// about how to estalish a tunnel connection to the server through
// several protocols. ServerEntry are JSON records downloaded from
// various sources.
type ServerEntry struct {
	ipAddress                     string   `json:"ipAddress"`
	webServerPort                 string   `json:"webServerPort"` // not an int
	webServerSecret               string   `json:"webServerSecret"`
	webServerCertificate          string   `json:"webServerCertificate"`
	sshPort                       int      `json:"sshPort"`
	sshUsername                   string   `json:"sshUsername"`
	sshPassword                   string   `json:"sshPassword"`
	sshHostKey                    string   `json:"sshHostKey"`
	sshObfuscatedPort             int      `json:"sshObfuscatedPort"`
	sshObfuscatedKey              string   `json:"sshObfuscatedKey"`
	capabilities                  []string `json:"capabilities"`
	region                        string   `json:"region"`
	meekServerPort                int      `json:"meekServerPort"`
	meekCookieEncryptionPublicKey string   `json:"meekCookieEncryptionPublicKey"`
	meekObfuscatedKey             string   `json:"meekObfuscatedKey"`
	meekFrontingDomain            string   `json:"meekFrontingDomain"`
	meekFrontingHost              string   `json:"meekFrontingHost"`
}
