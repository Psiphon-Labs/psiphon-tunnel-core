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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
)

func main() {

	var configFilename string
	flag.StringVar(&configFilename, "config", "", "OSL configuration file")

	var offset time.Duration
	flag.DurationVar(&offset, "offset", 0, "pave OSL start time (offset from now)")

	var period time.Duration
	flag.DurationVar(&period, "period", 0, "pave OSL total period (starting from offset)")

	var signingKeyPairFilename string
	flag.StringVar(&signingKeyPairFilename, "key", "", "signing public key pair")

	var destinationDirectory string
	flag.StringVar(&destinationDirectory, "output", "", "destination directory for output files")

	flag.Parse()

	configJSON, err := ioutil.ReadFile(configFilename)
	if err != nil {
		fmt.Printf("failed loading configuration file: %s\n", err)
		os.Exit(1)
	}

	config, err := osl.LoadConfig(configJSON)
	if err != nil {
		fmt.Printf("failed processing configuration file: %s\n", err)
		os.Exit(1)
	}

	keyPairPEM, err := ioutil.ReadFile(signingKeyPairFilename)
	if err != nil {
		fmt.Printf("failed loading signing public key pair file: %s\n", err)
		os.Exit(1)
	}

	// Password "none" from psi_ops:
	// https://bitbucket.org/psiphon/psiphon-circumvention-system/src/ef4f3d4893bd5259ef24f0cb4525cbbbb0854cf9/Automation/psi_ops.py?at=default&fileviewer=file-view-default#psi_ops.py-297

	block, _ := pem.Decode(keyPairPEM)
	decryptedKeyPairPEM, err := x509.DecryptPEMBlock(block, []byte("none"))
	if err != nil {
		fmt.Printf("failed decrypting signing public key pair file: %s\n", err)
		os.Exit(1)
	}

	rsaKey, err := x509.ParsePKCS1PrivateKey(decryptedKeyPairPEM)
	if err != nil {
		fmt.Printf("failed parsing signing public key pair file: %s\n", err)
		os.Exit(1)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(rsaKey.Public())
	if err != nil {
		fmt.Printf("failed marshaling signing public key: %s\n", err)
		os.Exit(1)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)

	signingPublicKey := base64.StdEncoding.EncodeToString(publicKeyBytes)
	signingPrivateKey := base64.StdEncoding.EncodeToString(privateKeyBytes)

	paveTime := time.Now().UTC()
	startTime := paveTime.Add(offset)
	endTime := startTime.Add(period)

	schemeOSLTimePeriods := make(map[int]time.Duration)
	for index, scheme := range config.Schemes {
		slokTimePeriodsPerOSL := 1
		for _, keySplit := range scheme.SeedPeriodKeySplits {
			slokTimePeriodsPerOSL *= keySplit.Total
		}
		schemeOSLTimePeriods[index] =
			time.Duration(scheme.SeedPeriodNanoseconds * int64(slokTimePeriodsPerOSL))
	}

	allPropagationChannelIDs := make(map[string][]int)
	for index, scheme := range config.Schemes {
		for _, propagationChannelID := range scheme.PropagationChannelIDs {
			allPropagationChannelIDs[propagationChannelID] =
				append(allPropagationChannelIDs[propagationChannelID], index)
		}
	}

	for propagationChannelID, schemeIndexes := range allPropagationChannelIDs {

		paveServerEntries := make([]map[time.Time]string, len(config.Schemes))

		for _, index := range schemeIndexes {

			paveServerEntries[index] = make(map[time.Time]string)

			oslTime, _ := time.Parse(time.RFC3339, config.Schemes[index].Epoch)
			for !oslTime.After(endTime) {
				if !oslTime.Before(startTime) {
					paveServerEntries[index][oslTime] = ""
				}
				oslTime = oslTime.Add(schemeOSLTimePeriods[index])
			}

			fmt.Printf("Paving propagation channel %s, scheme #%d, [%s - %s], %s\n",
				propagationChannelID, index, startTime, endTime, schemeOSLTimePeriods[index])
		}

		paveFiles, err := config.Pave(
			endTime,
			propagationChannelID,
			signingPublicKey,
			signingPrivateKey,
			paveServerEntries,
			func(schemeIndex int, oslTime time.Time, fileName string) {
				fmt.Printf("\tPaved scheme %d %s: %s\n", schemeIndex, oslTime, fileName)
			})
		if err != nil {
			fmt.Printf("failed paving: %s\n", err)
			os.Exit(1)
		}

		directory := filepath.Join(destinationDirectory, propagationChannelID)

		err = os.MkdirAll(directory, 0755)
		if err != nil {
			fmt.Printf("failed creating output directory: %s\n", err)
			os.Exit(1)
		}

		for _, paveFile := range paveFiles {
			filename := filepath.Join(directory, paveFile.Name)
			err = ioutil.WriteFile(filename, paveFile.Contents, 0755)
			if err != nil {
				fmt.Printf("error writing output file: %s\n", err)
				os.Exit(1)
			}
		}
	}
}
