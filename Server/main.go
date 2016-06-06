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
	"strconv"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server"
)

func main() {

	var generateServerIPaddress, generateServerNetworkInterface string
	var generateConfigFilename, generateServerEntryFilename string
	var generateWebServerPort int
	var generateProtocolPorts stringListFlag
	var runConfigFilenames stringListFlag

	flag.StringVar(
		&generateConfigFilename,
		"newConfig",
		server.SERVER_CONFIG_FILENAME,
		"generate new config with this `filename`")

	flag.StringVar(
		&generateServerEntryFilename,
		"newServerEntry",
		server.SERVER_ENTRY_FILENAME,
		"generate new server entry with this `filename`")

	flag.StringVar(
		&generateServerNetworkInterface,
		"interface",
		"",
		"generate with server IP address from this `network-interface`")

	flag.StringVar(
		&generateServerIPaddress,
		"ipaddress",
		server.DEFAULT_SERVER_IP_ADDRESS,
		"generate with this server `IP address`")

	flag.IntVar(
		&generateWebServerPort,
		"web",
		0,
		"generate with web server `port`; 0 for no web server")

	flag.Var(
		&generateProtocolPorts,
		"protocol",
		"generate with `protocol:port`; flag may be repeated to enable multiple protocols")

	flag.Var(
		&runConfigFilenames,
		"config",
		"run with this config `filename`; flag may be repeated to load multiple config files")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage:\n\n"+
				"%s <flags> generate    generates a configuration and server entry\n"+
				"%s <flags> run         runs configured services\n\n",
			os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	args := flag.Args()

	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	} else if args[0] == "generate" {

		serverIPaddress := generateServerIPaddress

		if generateServerNetworkInterface != "" {
			var err error
			serverIPaddress, err = psiphon.GetInterfaceIPAddress(generateServerNetworkInterface)
			fmt.Printf("generate failed: %s\n", err)
			os.Exit(1)
		}

		tunnelProtocolPorts := make(map[string]int)
		for _, protocolPort := range generateProtocolPorts {
			parts := strings.Split(protocolPort, ":")
			if len(parts) == 2 {
				port, err := strconv.Atoi(parts[1])
				if err != nil {
					fmt.Printf("generate failed: %s\n", err)
					os.Exit(1)
				}
				tunnelProtocolPorts[parts[0]] = port
			}
		}

		configFileContents, serverEntryFileContents, err :=
			server.GenerateConfig(
				serverIPaddress,
				generateWebServerPort,
				tunnelProtocolPorts)
		if err != nil {
			fmt.Printf("generate failed: %s\n", err)
			os.Exit(1)
		}

		err = ioutil.WriteFile(generateConfigFilename, configFileContents, 0600)
		if err != nil {
			fmt.Printf("error writing configuration file: %s\n", err)
			os.Exit(1)
		}

		err = ioutil.WriteFile(generateServerEntryFilename, serverEntryFileContents, 0600)
		if err != nil {
			fmt.Printf("error writing server entry file: %s\n", err)
			os.Exit(1)
		}

	} else if args[0] == "run" {

		if len(runConfigFilenames) == 0 {
			runConfigFilenames = []string{server.SERVER_CONFIG_FILENAME}
		}

		var configFileContents [][]byte

		for _, configFilename := range runConfigFilenames {
			contents, err := ioutil.ReadFile(configFilename)
			if err != nil {
				fmt.Printf("error loading configuration file: %s\n", err)
				os.Exit(1)
			}

			configFileContents = append(configFileContents, contents)
		}

		err := server.RunServices(configFileContents)
		if err != nil {
			fmt.Printf("run failed: %s\n", err)
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
