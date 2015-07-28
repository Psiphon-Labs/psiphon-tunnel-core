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
	"time"
)

// TODO: allow all params to be configured

const (
	VERSION                                      = "0.0.9"
	DATA_STORE_FILENAME                          = "psiphon.db"
	CONNECTION_WORKER_POOL_SIZE                  = 10
	TUNNEL_POOL_SIZE                             = 1
	TUNNEL_CONNECT_TIMEOUT                       = 15 * time.Second
	TUNNEL_READ_TIMEOUT                          = 0 * time.Second
	TUNNEL_WRITE_TIMEOUT                         = 5 * time.Second
	TUNNEL_OPERATE_SHUTDOWN_TIMEOUT              = 2 * time.Second
	TUNNEL_PORT_FORWARD_DIAL_TIMEOUT             = 10 * time.Second
	TUNNEL_SSH_KEEP_ALIVE_PAYLOAD_MAX_BYTES      = 256
	TUNNEL_SSH_KEEP_ALIVE_PERIOD_MIN             = 60 * time.Second
	TUNNEL_SSH_KEEP_ALIVE_PERIOD_MAX             = 120 * time.Second
	TUNNEL_SSH_KEEP_ALIVE_TIMEOUT                = 10 * time.Second
	ESTABLISH_TUNNEL_TIMEOUT_SECONDS             = 300
	ESTABLISH_TUNNEL_WORK_TIME_SECONDS           = 60 * time.Second
	ESTABLISH_TUNNEL_PAUSE_PERIOD                = 5 * time.Second
	PORT_FORWARD_FAILURE_THRESHOLD               = 10
	HTTP_PROXY_ORIGIN_SERVER_TIMEOUT             = 15 * time.Second
	HTTP_PROXY_MAX_IDLE_CONNECTIONS_PER_HOST     = 50
	FETCH_REMOTE_SERVER_LIST_TIMEOUT             = 10 * time.Second
	FETCH_REMOTE_SERVER_LIST_RETRY_PERIOD        = 5 * time.Second
	FETCH_REMOTE_SERVER_LIST_STALE_PERIOD        = 6 * time.Hour
	PSIPHON_API_CLIENT_SESSION_ID_LENGTH         = 16
	PSIPHON_API_SERVER_TIMEOUT                   = 20 * time.Second
	PSIPHON_API_STATUS_REQUEST_PERIOD_MIN        = 5 * time.Minute
	PSIPHON_API_STATUS_REQUEST_PERIOD_MAX        = 10 * time.Minute
	PSIPHON_API_STATUS_REQUEST_PADDING_MAX_BYTES = 256
	PSIPHON_API_CONNECTED_REQUEST_PERIOD         = 24 * time.Hour
	PSIPHON_API_CONNECTED_REQUEST_RETRY_PERIOD   = 5 * time.Second
	FETCH_ROUTES_TIMEOUT                         = 1 * time.Minute
	DOWNLOAD_UPGRADE_TIMEOUT                     = 15 * time.Minute
	DOWNLOAD_UPGRADE_RETRY_PAUSE_PERIOD          = 5 * time.Second
)

// To distinguish omitted timeout params from explicit 0 value timeout
// params, these params are int pointers. nil means no param was supplied
// so use the default; a non-nil pointer to 0 means no timeout.

type Config struct {
	LogFilename                         string
	DataStoreDirectory                  string
	DataStoreTempDirectory              string
	PropagationChannelId                string
	SponsorId                           string
	RemoteServerListUrl                 string
	RemoteServerListSignaturePublicKey  string
	ClientVersion                       string
	ClientPlatform                      string
	TunnelWholeDevice                   int
	EgressRegion                        string
	TunnelProtocol                      string
	EstablishTunnelTimeoutSeconds       *int
	LocalSocksProxyPort                 int
	LocalHttpProxyPort                  int
	ConnectionWorkerPoolSize            int
	TunnelPoolSize                      int
	PortForwardFailureThreshold         int
	UpstreamProxyUrl                    string
	NetworkConnectivityChecker          NetworkConnectivityChecker
	DeviceBinder                        DeviceBinder
	DnsServerGetter                     DnsServerGetter
	TargetServerEntry                   string
	DisableApi                          bool
	DisableRemoteServerListFetcher      bool
	SplitTunnelRoutesUrlFormat          string
	SplitTunnelRoutesSignaturePublicKey string
	SplitTunnelDnsServer                string
	UpgradeDownloadUrl                  string
	UpgradeDownloadFilename             string
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

	if config.DataStoreDirectory == "" {
		config.DataStoreDirectory, err = os.Getwd()
		if err != nil {
			return nil, ContextError(err)
		}
	}

	if config.ClientVersion == "" {
		config.ClientVersion = "0"
	}

	if config.TunnelProtocol != "" {
		if !Contains(SupportedTunnelProtocols, config.TunnelProtocol) {
			return nil, ContextError(
				errors.New("invalid tunnel protocol"))
		}
	}

	if config.EstablishTunnelTimeoutSeconds == nil {
		defaultEstablishTunnelTimeoutSeconds := ESTABLISH_TUNNEL_TIMEOUT_SECONDS
		config.EstablishTunnelTimeoutSeconds = &defaultEstablishTunnelTimeoutSeconds
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

	if config.NetworkConnectivityChecker != nil {
		return nil, ContextError(errors.New("NetworkConnectivityChecker interface must be set at runtime"))
	}

	if config.DeviceBinder != nil {
		return nil, ContextError(errors.New("DeviceBinder interface must be set at runtime"))
	}

	if config.DnsServerGetter != nil {
		return nil, ContextError(errors.New("DnsServerGetter interface must be set at runtime"))
	}

	return &config, nil
}
