/*
 * Copyright (c) 2019, Psiphon Inc.
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

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func main() {

	var publicKey string
	flag.StringVar(&publicKey, "public-key", "", "server entry signing public key")

	var privateKey string
	flag.StringVar(&privateKey, "private-key", "", "server entry signing private key")

	var encodedServerEntry string
	flag.StringVar(&encodedServerEntry, "server-entry", "", "encoded server entry")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage:\n\n"+
				"%s <flags> generate    generates and outputs a signing key pair\n"+
				"%s <flags> sign        signs a specified server entry with a specified key pair\n\n",
			os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	args := flag.Args()

	var command string
	if len(args) >= 1 {
		command = args[0]
	}

	var err error
	switch command {
	case "generate":
		err = generate()
	case "sign":
		if publicKey == "" || privateKey == "" || encodedServerEntry == "" {
			flag.Usage()
			os.Exit(1)
		}
		err = sign(publicKey, privateKey, encodedServerEntry)
	default:
		flag.Usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
}

func generate() error {

	publicKey, privateKey, err := protocol.NewServerEntrySignatureKeyPair()
	if err != nil {
		return fmt.Errorf("generate key pair failed: %s", err)
	}

	fmt.Printf("public-key:    %s\nprivate-key:   %s\n\n", publicKey, privateKey)

	return nil
}

func sign(publicKey, privateKey, encodedServerEntry string) error {

	serverEntryFields, err := protocol.DecodeServerEntryFields(encodedServerEntry, "", "")
	if err != nil {
		return fmt.Errorf("decode server entry failed: %s", err)
	}

	err = serverEntryFields.AddSignature(publicKey, privateKey)
	if err != nil {
		return fmt.Errorf("add signature failed: %s", err)
	}

	encodedSignedServerEntry, err := protocol.EncodeServerEntryFields(serverEntryFields)
	if err != nil {
		return fmt.Errorf("encode server entry failed: %s", err)
	}

	fmt.Printf("%s\n\n", encodedSignedServerEntry)

	return nil
}
