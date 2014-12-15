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

package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

func main() {

	var configFilename string
	flag.StringVar(&configFilename, "config", "", "configuration file")
	flag.Parse()
	if configFilename == "" {
		log.Fatalf("configuration file is required")
	}
	configFileContents, err := ioutil.ReadFile(configFilename)
	if err != nil {
		log.Fatalf("error loading configuration file: %s", err)
	}
	config, err := psiphon.LoadConfig(configFileContents)
	if err != nil {
		log.Fatalf("error processing configuration file: %s", err)
	}

	err = psiphon.InitDataStore(config.DataStoreFilename)
	if err != nil {
		log.Fatalf("error initializing datastore: %s", err)
	}

	if config.LogFilename != "" {
		logFile, err := os.OpenFile(config.LogFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("error opening log file: %s", err)
		}
		defer logFile.Close()
		log.SetOutput(logFile)
	}

	controller := psiphon.NewController(config)
	shutdownBroadcast := make(chan struct{})
	controllerWaitGroup := new(sync.WaitGroup)
	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(shutdownBroadcast)
	}()

	systemStopSignal := make(chan os.Signal, 1)
	signal.Notify(systemStopSignal, os.Interrupt, os.Kill)
	<-systemStopSignal

	psiphon.Notice(psiphon.NOTICE_INFO, "shutdown by system")
	close(shutdownBroadcast)
	controllerWaitGroup.Wait()
}
