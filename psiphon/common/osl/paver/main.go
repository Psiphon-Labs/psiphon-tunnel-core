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

	var scheme int
	flag.IntVar(&scheme, "scheme", 0, "scheme to pave")

	var oslOffset int
	flag.IntVar(&oslOffset, "offset", 0, "OSL offset")

	var oslCount int
	flag.IntVar(&oslCount, "count", 1, "OSL count")

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

	if scheme < 0 || scheme >= len(config.Schemes) {
		fmt.Printf("failed: invalid scheme\n")
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

	slokTimePeriodsPerOSL := 1
	for _, keySplit := range config.Schemes[scheme].SeedPeriodKeySplits {
		slokTimePeriodsPerOSL *= keySplit.Total
	}
	oslTimePeriod := time.Duration(config.Schemes[0].SeedPeriodNanoseconds * int64(slokTimePeriodsPerOSL))

	for _, propagationChannelID := range config.Schemes[0].PropagationChannelIDs {

		paveServerEntries := make([]map[time.Time]string, len(config.Schemes))
		paveServerEntries[0] = make(map[time.Time]string)

		epoch, _ := time.Parse(time.RFC3339, config.Schemes[0].Epoch)
		for i := oslOffset; i < oslOffset+oslCount; i++ {
			paveServerEntries[0][epoch.Add(time.Duration(i)*oslTimePeriod)] = ""
		}

		paveFiles, err := config.Pave(
			epoch.Add(time.Duration(oslCount)*oslTimePeriod),
			propagationChannelID,
			signingPublicKey,
			signingPrivateKey,
			paveServerEntries)
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
