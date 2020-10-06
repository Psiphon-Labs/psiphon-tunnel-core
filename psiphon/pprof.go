// +build PSIPHON_RUN_PPROF

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

package psiphon

import (
	"net/http"
	_ "net/http/pprof"
	"sync"
)

var pprofRunOnce sync.Once

func pprofRun() {
	pprofRunOnce.Do(func() {
		go func() {
			NoticeInfo("Running http://localhost:6060/debug/pprof/")
			NoticeInfo("pprofRun: %s", http.ListenAndServe("localhost:6060", nil))
		}()
	})
}
