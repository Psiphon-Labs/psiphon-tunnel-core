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
	"encoding/json"
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
	flag.StringVar(&configFilename, "config", "", "OSL configuration filename")

	var offset time.Duration
	flag.DurationVar(
		&offset, "offset", 0,
		"pave OSL start time (offset from now); default, 0, selects earliest epoch")

	var period time.Duration
	flag.DurationVar(
		&period, "period", 0,
		"pave OSL total period (starting from offset); default, 0, selects at least one OSL period from now for all schemes")

	var signingKeyPairFilename string
	flag.StringVar(&signingKeyPairFilename, "key", "", "signing public key pair filename")

	var payloadFilename string
	flag.StringVar(&payloadFilename, "payload", "", "server entries to pave into OSLs")

	var destinationDirectory string
	flag.StringVar(
		&destinationDirectory, "output", "",
		"destination directory for output files; when omitted, no files are written (dry run mode)")

	var listScheme int
	flag.IntVar(&listScheme, "list-scheme", -1, "list current period OSL IDs for specified scheme; no files are written")

	flag.Parse()

	// load config

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

	if listScheme != -1 {
		OSLIDs, err := config.CurrentOSLIDs(listScheme)
		if err != nil {
			fmt.Printf("failed listing scheme OSL IDs: %s\n", err)
			os.Exit(1)
		}
		for propagationChannelID, OSLID := range OSLIDs {
			fmt.Printf("%s %s\n", propagationChannelID, OSLID)
		}
		return
	}

	// load key pair

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

	// load payload

	paveServerEntries := make(map[string][]string)

	pavedPayloadOSLID := make(map[string]bool)

	if payloadFilename != "" {
		payloadJSON, err := ioutil.ReadFile(payloadFilename)
		if err != nil {
			fmt.Printf("failed loading payload file: %s\n", err)
			os.Exit(1)
		}

		var payload []*struct {
			OSLIDs      []string
			ServerEntry string
		}

		err = json.Unmarshal(payloadJSON, &payload)
		if err != nil {
			fmt.Printf("failed unmarshaling payload file: %s\n", err)
			os.Exit(1)
		}

		for _, item := range payload {
			for _, oslID := range item.OSLIDs {
				paveServerEntries[oslID] = append(
					paveServerEntries[oslID], item.ServerEntry)
				pavedPayloadOSLID[oslID] = false
			}
		}
	}

	// determine pave time range

	paveTime := time.Now().UTC()

	var startTime, endTime time.Time

	if offset != 0 {
		startTime = paveTime.Add(offset)
	} else {
		// Default to the earliest scheme epoch.
		startTime = paveTime
		for _, scheme := range config.Schemes {
			epoch, _ := time.Parse(time.RFC3339, scheme.Epoch)
			if epoch.Before(startTime) {
				startTime = epoch
			}
		}
	}

	if period != 0 {
		endTime = startTime.Add(period)
	} else {
		// Default to at least one OSL period after "now",
		// considering all schemes.
		endTime = paveTime
		for _, scheme := range config.Schemes {
			oslDuration := scheme.GetOSLDuration()
			if endTime.Add(oslDuration).After(endTime) {
				endTime = endTime.Add(oslDuration)
			}
		}
	}

	// build list of all participating propagation channel IDs

	allPropagationChannelIDs := make(map[string]bool)
	for _, scheme := range config.Schemes {
		for _, propagationChannelID := range scheme.PropagationChannelIDs {
			allPropagationChannelIDs[propagationChannelID] = true
		}
	}

	// pave a directory for each propagation channel

	for propagationChannelID := range allPropagationChannelIDs {

		paveFiles, err := config.Pave(
			endTime,
			propagationChannelID,
			signingPublicKey,
			signingPrivateKey,
			paveServerEntries,
			func(logInfo *osl.PaveLogInfo) {
				pavedPayloadOSLID[logInfo.OSLID] = true
				fmt.Printf(
					"paved %s: scheme %d, propagation channel ID %s, "+
						"OSL time %s, OSL duration %s, server entries: %d\n",
					logInfo.FileName,
					logInfo.SchemeIndex,
					logInfo.PropagationChannelID,
					logInfo.OSLTime,
					logInfo.OSLDuration,
					logInfo.ServerEntryCount)
			})
		if err != nil {
			fmt.Printf("failed paving: %s\n", err)
			os.Exit(1)
		}

		if destinationDirectory != "" {

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

	// fail if payload contains OSL IDs not in the config and time range

	unknown := false
	for oslID, paved := range pavedPayloadOSLID {
		if !paved {
			fmt.Printf(
				"ignored %d server entries for unknown OSL ID: %s\n",
				len(paveServerEntries[oslID]),
				oslID)
			unknown = true
		}
	}
	if unknown {
		fmt.Printf("payload contains unknown OSL IDs\n")
		os.Exit(1)
	}
}
