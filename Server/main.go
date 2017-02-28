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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Psiphon-Inc/panicwrap"
	"github.com/Psiphon-Inc/rotate-safe-writer"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server"
)

var loadedConfigJSON []byte

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
			serverIPaddress, err = common.GetInterfaceIPAddress(generateServerNetworkInterface)
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

		loadedConfigJSON = configJSON

		// Comments from: https://github.com/mitchellh/panicwrap#usage
		// Unhandled panic wrapper. Logs it, then re-executes the current executable
		exitStatus, err := panicwrap.Wrap(&panicwrap.WrapConfig{
			Handler:        panicHandler,
			ForwardSignals: []os.Signal{os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGTSTP, syscall.SIGCONT},
		})
		if err != nil {
			fmt.Printf("failed to set up the panic wrapper: %s\n", err)
			os.Exit(1)
		}

		// If exitStatus >= 0, then we're the parent process and the panicwrap
		// re-executed ourselves and completed. Just exit with the proper status.
		if exitStatus >= 0 {
			os.Exit(exitStatus)
		}
		// Otherwise, exitStatus < 0 means we're the child. Continue executing as normal

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

func panicHandler(output string) {
	if len(loadedConfigJSON) > 0 {
		config, err := server.LoadConfig([]byte(loadedConfigJSON))
		if err != nil {
			fmt.Printf("error parsing configuration file: %s\n%s\n", err, output)
			os.Exit(1)
		}

		logEvent := make(map[string]string)
		logEvent["host_id"] = config.HostID
		logEvent["build_rev"] = common.GetBuildInfo().BuildRev
		logEvent["timestamp"] = time.Now().Format(time.RFC3339)
		logEvent["event_name"] = "panic"
		logEvent["panic"] = output

		// Logs are written to the configured file name. If no name is specified, logs are written to stderr
		var jsonWriter io.Writer
		if config.LogFilename != "" {
			panicLog, err := rotate.NewRotatableFileWriter(config.LogFilename, 0666)
			if err != nil {
				fmt.Printf("unable to set panic log output: %s\n%s\n", err, output)
				os.Exit(1)
			}
			defer panicLog.Close()

			jsonWriter = panicLog
		} else {
			jsonWriter = os.Stderr
		}

		enc := json.NewEncoder(jsonWriter)
		err = enc.Encode(logEvent)
		if err != nil {
			fmt.Printf("unable to serialize panic message to JSON: %s\n%s\n", err, output)
			os.Exit(1)
		}
	} else {
		fmt.Printf("no configuration JSON was loaded, cannot continue\n%s\n", output)
		os.Exit(1)
	}

	os.Exit(1)
}
