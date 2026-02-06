/*
 * Copyright (c) 2026, Psiphon Inc.
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
	"io"
	"os"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/push"
)

func main() {

	var configFile string
	flag.StringVar(&configFile, "config", "", "Psiphon config file")

	var ttl time.Duration
	flag.DurationVar(&ttl, "TTL", 24*time.Hour, "payload TTL")

	var source string
	flag.StringVar(&source, "source", "push-converter", "payload source")

	var prioritize bool
	flag.BoolVar(&prioritize, "prioritize", false, "prioritize dials for all payload server entries")

	var minPadding int
	flag.IntVar(&minPadding, "minPadding", 0, "min obfuscated payload padding")

	var maxPadding int
	flag.IntVar(&maxPadding, "maxPadding", 0, "max obfuscated payload padding")

	flag.Parse()

	obfuscationKey := os.Getenv("PSIPHON_PUSH_PAYLOAD_OBFUSCATION_KEY")
	signaturePublicKey := os.Getenv("PSIPHON_PUSH_PAYLOAD_SIGNATURE_PUBLIC_KEY")
	signaturePrivateKey := os.Getenv("PSIPHON_PUSH_PAYLOAD_SIGNATURE_PRIVATE_KEY")

	if configFile != "" {
		config, err := loadConfig(configFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, errors.Trace(err))
			os.Exit(1)
		}
		if config.PushPayloadObfuscationKey != "" {
			obfuscationKey = config.PushPayloadObfuscationKey
		}
		if config.PushPayloadSignaturePublicKey != "" {
			signaturePublicKey = config.PushPayloadSignaturePublicKey
		}
	}

	inputFile := flag.Arg(0)
	if inputFile == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	err := convert(
		obfuscationKey,
		minPadding,
		maxPadding,
		signaturePublicKey,
		signaturePrivateKey,
		inputFile,
		ttl,
		source,
		prioritize)
	if err != nil {
		fmt.Fprintln(os.Stderr, errors.Trace(err))
		os.Exit(1)
	}

	os.Exit(0)
}

func convert(
	obfuscationKey string,
	minPadding int,
	maxPadding int,
	signaturePublicKey string,
	signaturePrivateKey string,
	inputFile string,
	ttl time.Duration,
	source string,
	prioritize bool) error {

	input, err := os.ReadFile(inputFile)
	if err != nil {
		return errors.Trace(err)
	}

	// If the input file is a valid server entry list, convert to a push
	// payload. Otherwise assume the input is a push payload and convert to a
	// server entry list.

	serverEntryFields, err := decodeServerEntryList(string(input))
	if err == nil {

		var prioritizedServerEntries []*push.PrioritizedServerEntry
		for _, serverEntry := range serverEntryFields {
			packed, err := protocol.EncodePackedServerEntryFields(serverEntry)
			if err != nil {
				return errors.Trace(err)
			}

			prioritizedServerEntries = append(prioritizedServerEntries,
				&push.PrioritizedServerEntry{
					ServerEntryFields: packed,
					Source:            source,
					PrioritizeDial:    prioritize,
				})
		}

		payloads, err := push.MakePushPayloads(
			obfuscationKey,
			minPadding,
			maxPadding,
			signaturePublicKey,
			signaturePrivateKey,
			ttl,
			[][]*push.PrioritizedServerEntry{
				prioritizedServerEntries})
		if err != nil {
			return errors.Trace(err)
		}

		os.Stdout.Write(payloads[0])
		return nil
	}

	var serverList []string
	importer := func(
		packed protocol.PackedServerEntryFields,
		_ string,
		_ bool) error {

		serverEntryFields, err := protocol.DecodePackedServerEntryFields(packed)
		if err != nil {
			return errors.Trace(err)
		}

		serverEntry, err := protocol.EncodeServerEntryFields(serverEntryFields)
		if err != nil {
			return errors.Trace(err)
		}

		serverList = append(serverList, serverEntry)
		return nil
	}

	_, err = push.ImportPushPayload(
		obfuscationKey,
		signaturePublicKey,
		input,
		importer)
	if err != nil {
		return errors.Trace(err)
	}

	os.Stdout.Write([]byte(strings.Join(serverList, "\n")))
	return nil
}

// decodeServerEntryList is equivalent to protocol.DecodeServerEntryList
// without local field initialization/validation.
func decodeServerEntryList(
	encodedServerEntryList string) ([]protocol.ServerEntryFields, error) {

	serverEntries := make([]protocol.ServerEntryFields, 0)
	for _, encodedServerEntry := range strings.Split(
		encodedServerEntryList, "\n") {

		if len(encodedServerEntry) == 0 {
			continue
		}

		serverEntryFields, err := protocol.DecodeServerEntryFields(
			encodedServerEntry, "", "")
		if err != nil {
			return nil, errors.Trace(err)
		}

		serverEntries = append(serverEntries, serverEntryFields)
	}
	return serverEntries, nil
}

func loadConfig(configFile string) (*psiphon.Config, error) {

	psiphon.SetNoticeWriter(io.Discard)

	configJSON, err := os.ReadFile(configFile)
	if err != nil {
		return nil, errors.Trace(err)
	}
	config, err := psiphon.LoadConfig(configJSON)
	if err != nil {
		return nil, errors.Trace(err)
	}
	err = config.Commit(false)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return config, nil
}
