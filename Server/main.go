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
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server"
)

func main() {

	var generateServerIPaddress string
	var generateWebServerPort, generateSSHServerPort, generateObfuscatedSSHServerPort int
	var runConfigFilenames stringListFlag

	flag.StringVar(
		&generateServerIPaddress,
		"ipaddress",
		server.DEFAULT_SERVER_IP_ADDRESS,
		"generate with this server `IP address`")

	flag.IntVar(
		&generateWebServerPort,
		"webport",
		server.DEFAULT_WEB_SERVER_PORT,
		"generate with this web server `port`; 0 for no web server")

	flag.IntVar(
		&generateSSHServerPort,
		"sshport",
		server.DEFAULT_SSH_SERVER_PORT,
		"generate with this SSH server `port`; 0 for no SSH server")

	flag.IntVar(
		&generateObfuscatedSSHServerPort,
		"osshport",
		server.DEFAULT_OBFUSCATED_SSH_SERVER_PORT,
		"generate with this Obfuscated SSH server `port`; 0 for no Obfuscated SSH server")

	flag.Var(
		&runConfigFilenames,
		"config",
		"run with this config `filename`; may be repeated to load multiple config files")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage:\n\n"+
				"%s generate    generates a configuration and server entry\n"+
				"%s run         runs configured services\n\n",
			os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	args := flag.Args()

	configFilename := server.SERVER_CONFIG_FILENAME

	serverEntryFilename := server.SERVER_ENTRY_FILENAME

	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	} else if args[0] == "generate" {

		configFileContents, serverEntryFileContents, err := server.GenerateConfig(
			&server.GenerateConfigParams{
				ServerIPAddress:         generateServerIPaddress,
				WebServerPort:           generateWebServerPort,
				SSHServerPort:           generateSSHServerPort,
				ObfuscatedSSHServerPort: generateObfuscatedSSHServerPort,
			})

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

		if len(runConfigFilenames) == 0 {
			runConfigFilenames = []string{configFilename}
		}

		var configFileContents [][]byte

		for _, configFilename := range runConfigFilenames {
			ccontents, err := ioutil.ReadFile(configFilename)
			if err != nil {
				fmt.Errorf("error loading configuration file: %s", err)
				os.Exit(1)
			}

			configFileContents = append(configFileContents, ccontents)
		}

		err := server.RunServices(configFileContents)
		if err != nil {
			fmt.Errorf("run failed: %s", err)
			os.Exit(1)
		}
	}
}

type stringListFlag []string

func (list *stringListFlag) String() string {
	return strings.Join(*list, ", ")
}

func (list *stringListFlag) Set(flagValue string) error {
	*list = append(*list, flagValue)
	return nil
}
