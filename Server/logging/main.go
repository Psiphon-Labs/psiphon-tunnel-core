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

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/Server/logging/analysis"
)

type stringListFlag []string

func (list *stringListFlag) String() string {
	return strings.Join(*list, ", ")
}

func (list *stringListFlag) Set(flagValue string) error {
	*list = append(*list, flagValue)
	return nil
}

func main() {

	var logFileList stringListFlag
	var printMessages bool
	var printMetrics bool
	var printUnknowns bool
	var printStructure bool
	var printExample bool

	flag.Var(
		&logFileList,
		"file",
		"file to analyze; flag may be repeated to analyze multiple files")

	flag.BoolVar(
		&printMessages,
		"messages",
		false,
		"display message type logs")

	flag.BoolVar(
		&printMetrics,
		"metrics",
		false,
		"display metric type logs")

	flag.BoolVar(
		&printUnknowns,
		"unknown",
		false,
		"display logs of an unknown type")

	flag.BoolVar(
		&printStructure,
		"structure",
		false,
		"print each log model with its key graph structure")

	flag.BoolVar(
		&printExample,
		"example",
		false,
		"print each log model with an example")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage:\n\n"+
				"%s <flags>\n"+
				os.Args[0], os.Args[0]+"\n\n")
		fmt.Printf("\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if len(logFileList) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	logFileStats := analysis.NewLogStatsFromFiles(logFileList)
	logFileStats.Print(printMessages, printMetrics, printUnknowns, printStructure, printExample)

	fmt.Printf("Found %d messages, %d metrics and %d unknown logs with a total of %d distinct types of logs\n",
		logFileStats.MessageLogModels.Count,
		logFileStats.MetricsLogModels.Count,
		logFileStats.UnknownLogModels.Count,
		logFileStats.NumDistinctLogs())
}
