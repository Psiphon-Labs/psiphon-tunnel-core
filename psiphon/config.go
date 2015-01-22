/*
 * Copyright (c) 2015, Psiphon Inc.
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
	"os"
)

type Config struct {
	LogFilename                        string
	DataStoreDirectory                 string
	DataStoreTempDirectory             string
	PropagationChannelId               string
	SponsorId                          string
	RemoteServerListUrl                string
	RemoteServerListSignaturePublicKey string
	ClientVersion                      string
	ClientPlatform                     string
	TunnelWholeDevice                  int
	EgressRegion                       string
	TunnelProtocol                     string
	LocalSocksProxyPort                int
	LocalHttpProxyPort                 int
	ConnectionWorkerPoolSize           int
	TunnelPoolSize                     int
	PortForwardFailureThreshold        int
	UpstreamHttpProxyAddress           string
	BindToDeviceProvider               DeviceBinder
	BindToDeviceDnsServer              string
}

// LoadConfig parses and validates a JSON format Psiphon config JSON
// string and returns a Config struct populated with config values.
func LoadConfig(configJson []byte) (*Config, error) {
	var config Config
	err := json.Unmarshal(configJson, &config)
	if err != nil {
		return nil, ContextError(err)
	}

	// These fields are required; the rest are optional
	if config.PropagationChannelId == "" {
		return nil, ContextError(
			errors.New("propagation channel ID is missing from the configuration file"))
	}
	if config.SponsorId == "" {
		return nil, ContextError(
			errors.New("sponsor ID is missing from the configuration file"))
	}
	if config.RemoteServerListUrl == "" {
		return nil, ContextError(
			errors.New("remote server list URL is missing from the configuration file"))
	}
	if config.RemoteServerListSignaturePublicKey == "" {
		return nil, ContextError(
			errors.New("remote server list signature public key is missing from the configuration file"))
	}

	if config.DataStoreDirectory == "" {
		config.DataStoreDirectory, err = os.Getwd()
		if err != nil {
			return nil, ContextError(err)
		}
	}

	if config.TunnelProtocol != "" {
		if !Contains(SupportedTunnelProtocols, config.TunnelProtocol) {
			return nil, ContextError(
				errors.New("invalid tunnel protocol"))
		}
	}

	if config.ClientVersion == "" {
		config.ClientVersion = "0"
	}

	if config.ConnectionWorkerPoolSize == 0 {
		config.ConnectionWorkerPoolSize = CONNECTION_WORKER_POOL_SIZE
	}

	if config.TunnelPoolSize == 0 {
		config.TunnelPoolSize = TUNNEL_POOL_SIZE
	}

	if config.PortForwardFailureThreshold == 0 {
		config.PortForwardFailureThreshold = PORT_FORWARD_FAILURE_THRESHOLD
	}

	if config.BindToDeviceProvider != nil {
		return nil, ContextError(errors.New("interface must be set at runtime"))
	}

	return &config, nil
}
