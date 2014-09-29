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

import (
	"encoding/json"
	"errors"
	"io/ioutil"
)

type Config struct {
	LogFilename                        string
	PropagationChannelId               string
	SponsorId                          string
	RemoteServerListUrl                string
	RemoteServerListSignaturePublicKey string
	ClientVersion                      int
	ClientPlatform                     string
	TunnelWholeDevice                  int
	EgressRegion                       string
}

// LoadConfig reads, and parse, and validates a JSON format Psiphon config
// file and returns a Config struct populated with config values.
func LoadConfig(filename string) (*Config, error) {
	fileContents, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var config Config
	err = json.Unmarshal(fileContents, &config)
	if err != nil {
		return nil, err
	}
	if config.PropagationChannelId == "" {
		return nil, errors.New("propagation channel ID is missing from the configuration file")
	}
	if config.SponsorId == "" {
		return nil, errors.New("sponsor ID is missing from the configuration file")
	}
	if config.RemoteServerListUrl == "" {
		return nil, errors.New("remote server list URL is missing from the configuration file")
	}
	if config.RemoteServerListSignaturePublicKey == "" {
		return nil, errors.New("remote server list signature public key is missing from the configuration file")
	}
	return &config, nil
}
