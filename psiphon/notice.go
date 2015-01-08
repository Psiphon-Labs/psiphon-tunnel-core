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
	"fmt"
	"log"
)

const (
	NOTICE_INFO             = "INFO"
	NOTICE_ALERT            = "ALERT"
	NOTICE_VERSION          = "VERSION"
	NOTICE_TUNNELS          = "TUNNELS"
	NOTICE_SOCKS_PROXY_PORT = "SOCKS-PROXY-PORT"
	NOTICE_HTTP_PROXY_PORT  = "HTTP-PROXY-PORT"
	NOTICE_UPGRADE          = "UPGRADE"
	NOTICE_HOMEPAGE         = "HOMEPAGE"
	NOTICE_PAGE_VIEW_REGEX  = "PAGE-VIEW-REGEX"
	NOTICE_HTTPS_REGEX      = "HTTPS-REGEX"
)

func Notice(prefix, format string, args ...interface{}) {
	log.Printf("%s %s", prefix, fmt.Sprintf(format, args...))
}
