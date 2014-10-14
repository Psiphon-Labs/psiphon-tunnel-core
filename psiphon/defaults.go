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
	"time"
)

const (
	VERSION                                  = "0.0.2"
	DATA_STORE_FILENAME                      = "psiphon.db"
	FETCH_REMOTE_SERVER_LIST_TIMEOUT         = 5 * time.Second
	TUNNEL_CONNECT_TIMEOUT                   = 15 * time.Second
	TUNNEL_READ_TIMEOUT                      = 0 * time.Second
	TUNNEL_WRITE_TIMEOUT                     = 5 * time.Second
	TUNNEL_SSH_KEEP_ALIVE_PERIOD             = 60 * time.Second
	ESTABLISH_TUNNEL_TIMEOUT                 = 60 * time.Second
	CONNECTION_WORKER_POOL_SIZE              = 10
	HTTP_PROXY_ORIGIN_SERVER_TIMEOUT         = 15 * time.Second
	FETCH_REMOTE_SERVER_LIST_RETRY_TIMEOUT   = 5 * time.Second
	FETCH_REMOTE_SERVER_LIST_STALE_TIMEOUT   = 6 * time.Hour
	PSIPHON_API_CLIENT_SESSION_ID_LENGTH     = 16
	PSIPHON_API_SERVER_TIMEOUT               = 20 * time.Second
	HTTP_PROXY_MAX_IDLE_CONNECTIONS_PER_HOST = 50
)
