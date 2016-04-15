/*
 * Copyright (c) 2016, Psiphon Inc.
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

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server"
)

func main() {

	flag.Parse()

	args := flag.Args()

	// TODO: add working directory flag
	configFilename := server.SERVER_CONFIG_FILENAME
	serverEntryFilename := server.SERVER_ENTRY_FILENAME

	if len(args) < 1 {
		fmt.Errorf("usage: '%s generate' or '%s run'", os.Args[0])
		os.Exit(1)
	} else if args[0] == "generate" {

		// TODO: flags to set generate params
		configFileContents, serverEntryFileContents, err := server.GenerateConfig(
			&server.GenerateConfigParams{})
		if err != nil {
			fmt.Errorf("generate failed: %s", err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(configFilename, configFileContents, 0600)
		if err != nil {
			fmt.Errorf("error writing configuration file: %s", err)
			os.Exit(1)
		}

		err = ioutil.WriteFile(serverEntryFilename, serverEntryFileContents, 0600)
		if err != nil {
			fmt.Errorf("error writing server entry file: %s", err)
			os.Exit(1)
		}

	} else if args[0] == "run" {

		configFileContents, err := ioutil.ReadFile(configFilename)
		if err != nil {
			fmt.Errorf("error loading configuration file: %s", err)
			os.Exit(1)
		}

		err = server.RunServices(configFileContents)
		if err != nil {
			fmt.Errorf("run failed: %s", err)
			os.Exit(1)
		}
	}
}
