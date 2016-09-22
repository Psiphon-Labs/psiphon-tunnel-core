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

	var generateTrafficRulesFilename string
	var generateServerEntryFilename string
	var generateLogFilename string
	var generateServerIPaddress string
	var generateServerNetworkInterface string
	var generateWebServerPort int
	var generateProtocolPorts stringListFlag
	var configFilename string

	flag.StringVar(
		&generateTrafficRulesFilename,
		"trafficRules",
		server.SERVER_TRAFFIC_RULES_FILENAME,
		"generate with this traffic rules `filename`")

	flag.StringVar(
		&generateServerEntryFilename,
		"serverEntry",
		server.SERVER_ENTRY_FILENAME,
		"generate with this server entry `filename`")

	flag.StringVar(
		&generateLogFilename,
		"logFilename",
		"",
		"set application log file name and path; blank for stderr")

	flag.StringVar(
		&generateServerIPaddress,
		"ipaddress",
		server.DEFAULT_SERVER_IP_ADDRESS,
		"generate with this server `IP address`")

	flag.StringVar(
		&generateServerNetworkInterface,
		"interface",
		"",
		"generate with server IP address from this `network-interface`")

	flag.IntVar(
		&generateWebServerPort,
		"web",
		0,
		"generate with web server `port`; 0 for no web server")

	flag.Var(
		&generateProtocolPorts,
		"protocol",
		"generate with `protocol:port`; flag may be repeated to enable multiple protocols")

	flag.StringVar(
		&configFilename,
		"config",
		server.SERVER_CONFIG_FILENAME,
		"run or generate with this config `filename`")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage:\n\n"+
				"%s <flags> generate    generates configuration files\n"+
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
			if err != nil {
				fmt.Printf("generate failed: %s\n", err)
				os.Exit(1)
			}
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

		configJSON, trafficRulesJSON, encodedServerEntry, err :=
			server.GenerateConfig(
				&server.GenerateConfigParams{
					LogFilename:          generateLogFilename,
					ServerIPAddress:      serverIPaddress,
					EnableSSHAPIRequests: true,
					WebServerPort:        generateWebServerPort,
					TunnelProtocolPorts:  tunnelProtocolPorts,
					TrafficRulesFilename: generateTrafficRulesFilename,
				})
		if err != nil {
			fmt.Printf("generate failed: %s\n", err)
			os.Exit(1)
		}

		err = ioutil.WriteFile(configFilename, configJSON, 0600)
		if err != nil {
			fmt.Printf("error writing configuration file: %s\n", err)
			os.Exit(1)
		}

		err = ioutil.WriteFile(generateTrafficRulesFilename, trafficRulesJSON, 0600)
		if err != nil {
			fmt.Printf("error writing traffic rule configuration file: %s\n", err)
			os.Exit(1)
		}

		err = ioutil.WriteFile(generateServerEntryFilename, encodedServerEntry, 0600)
		if err != nil {
			fmt.Printf("error writing server entry file: %s\n", err)
			os.Exit(1)
		}

	} else if args[0] == "run" {

		configJSON, err := ioutil.ReadFile(configFilename)
		if err != nil {
			fmt.Printf("error loading configuration file: %s\n", err)
			os.Exit(1)
		}

		err = server.RunServices(configJSON)
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
