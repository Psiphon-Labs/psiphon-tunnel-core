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
	DATA_STORE_FILENAME                    = "psiphon.db"
	FETCH_REMOTE_SERVER_LIST_TIMEOUT       = 5 * time.Second
	CONNECTION_CANDIDATE_TIMEOUT           = 10 * time.Second
	ESTABLISH_TUNNEL_TIMEOUT               = 60 * time.Second
	CONNECTION_WORKER_POOL_SIZE            = 10
	TCP_KEEP_ALIVE_PERIOD_SECONDS          = 60
	FETCH_REMOTE_SERVER_LIST_RETRY_TIMEOUT = 5 * time.Second
	FETCH_REMOTE_SERVER_LIST_STALE_TIMEOUT = 6 * time.Hour
)
