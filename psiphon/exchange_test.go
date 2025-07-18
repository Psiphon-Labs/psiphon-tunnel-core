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

package psiphon

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func TestServerEntryExchange(t *testing.T) {

	// Prepare an empty database

	testDataDirName, err := ioutil.TempDir("", "psiphon-exchange-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(testDataDirName)

	err = SetNoticeWriter(io.Discard)
	if err != nil {
		t.Fatalf("error setting notice writer: %s", err)
	}
	defer ResetNoticeWriter()

	// Generate signing and exchange key material

	obfuscationKeyBytes, err := common.MakeSecureRandomBytes(32)
	if err != nil {
		t.Fatalf("MakeRandomBytes failed: %s", err)
	}

	obfuscationKey := base64.StdEncoding.EncodeToString(obfuscationKeyBytes)

	publicKey, privateKey, err := protocol.NewServerEntrySignatureKeyPair()
	if err != nil {
		t.Fatalf("NewServerEntrySignatureKeyPair failed: %s", err)
	}

	// Initialize config required for datastore operation

	networkID := prng.HexString(8)

	configJSONTemplate := `
		    {
                "SponsorId" : "0000000000000000",
                "PropagationChannelId" : "0000000000000000",
		        "ServerEntrySignaturePublicKey" : "%s",
		        "ExchangeObfuscationKey" : "%s",
		        "NetworkID" : "%s"
		    }`

	configJSON := fmt.Sprintf(
		configJSONTemplate,
		publicKey,
		obfuscationKey,
		networkID)

	config, err := LoadConfig([]byte(configJSON))
	if err != nil {
		t.Fatalf("LoadConfig failed: %s", err)
	}

	config.DataRootDirectory = testDataDirName

	err = config.Commit(false)
	if err != nil {
		t.Fatalf("Commit failed: %s", err)
	}

	resolver := NewResolver(config, true)
	defer resolver.Stop()
	config.SetResolver(resolver)

	err = OpenDataStore(config)
	if err != nil {
		t.Fatalf("OpenDataStore failed: %s", err)
	}
	defer CloseDataStore()

	// Generate server entries to test different cases
	//
	// Note: invalid signature cases are exercised in
	// protocol.TestServerEntryListSignatures

	makeServerEntryFields := func(IPAddress string) protocol.ServerEntryFields {
		n := 16
		fields := make(protocol.ServerEntryFields)
		fields["ipAddress"] = IPAddress
		fields["sshPort"] = 22
		fields["sshUsername"] = prng.HexString(n)
		fields["sshPassword"] = prng.HexString(n)
		fields["sshHostKey"] = prng.HexString(n)
		fields["sshObfuscatedPort"] = 23
		fields["sshObfuscatedQUICPort"] = 24
		fields["sshObfuscatedKey"] = prng.HexString(n)
		fields["capabilities"] = []string{"SSH", "OSSH", "QUIC", "ssh-api-requests"}
		fields["region"] = "US"
		fields["configurationVersion"] = 1
		return fields
	}

	serverEntry0 := makeServerEntryFields("192.168.1.1")
	tunnelProtocol0 := "SSH"

	serverEntry1 := makeServerEntryFields("192.168.1.2")
	err = serverEntry1.AddSignature(publicKey, privateKey)
	if err != nil {
		t.Fatalf("AddSignature failed: %s", err)
	}
	tunnelProtocol1 := "OSSH"

	serverEntry2 := makeServerEntryFields("192.168.1.3")
	err = serverEntry2.AddSignature(publicKey, privateKey)
	if err != nil {
		t.Fatalf("AddSignature failed: %s", err)
	}
	tunnelProtocol2 := "QUIC-OSSH"

	serverEntry3 := makeServerEntryFields("192.168.1.4")
	err = serverEntry3.AddSignature(publicKey, privateKey)
	if err != nil {
		t.Fatalf("AddSignature failed: %s", err)
	}
	tunnelProtocol3 := ""

	// paveServerEntry stores a server entry in the datastore with source
	// EMBEDDED, promotes the server entry to the affinity/export candidate
	// position, and generates and stores associated dial parameters when
	// specified. This creates potential candidates for export.
	//
	// When tunnelProtocol is "", no dial parameters are created.

	paveServerEntry := func(
		fields protocol.ServerEntryFields, tunnelProtocol string) {

		fields.SetLocalSource(protocol.SERVER_ENTRY_SOURCE_EMBEDDED)
		fields.SetLocalTimestamp(
			common.TruncateTimestampToHour(common.GetCurrentTimestamp()))

		err = StoreServerEntry(fields, true)
		if err != nil {
			t.Fatalf("StoreServerEntry failed: %s", err)
		}

		err = PromoteServerEntry(config, fields["ipAddress"].(string))
		if err != nil {
			t.Fatalf("PromoteServerEntry failed: %s", err)
		}

		if tunnelProtocol != "" {

			serverEntry, err := fields.GetServerEntry()
			if err != nil {
				t.Fatalf("ServerEntryFields.GetServerEntry failed: %s", err)
			}

			canReplay := func(serverEntry *protocol.ServerEntry, replayProtocol string) bool {
				return true
			}

			selectProtocol := func(serverEntry *protocol.ServerEntry) (string, bool) {
				return tunnelProtocol, true
			}

			dialParams, err := MakeDialParameters(
				config,
				nil,
				nil,
				nil,
				nil,
				canReplay,
				selectProtocol,
				serverEntry,
				nil,
				nil,
				false,
				0,
				0)
			if err != nil {
				t.Fatalf("MakeDialParameters failed: %s", err)
			}

			err = SetDialParameters(serverEntry.IpAddress, networkID, dialParams)
			if err != nil {
				t.Fatalf("SetDialParameters failed: %s", err)
			}
		}
	}

	// checkFirstServerEntry checks that the current affinity server entry has
	// the expected ID (IP address), and that any associated, stored dial
	// parameters are in the expected exchanged state. This is used to verify
	// that an import has succeed and set the datastore correctly.

	checkFirstServerEntry := func(
		fields protocol.ServerEntryFields, tunnelProtocol string, isExchanged bool) {

		_, iterator, err := NewServerEntryIterator(config)
		if err != nil {
			t.Fatalf("NewServerEntryIterator failed: %s", err)
		}
		defer iterator.Close()

		serverEntry, err := iterator.Next()
		if err != nil {
			t.Fatalf("ServerEntryIterator.Next failed: %s", err)
		}
		if serverEntry == nil {
			t.Fatalf("unexpected nil server entry")
		}

		if serverEntry.IpAddress != fields["ipAddress"] {
			t.Fatalf("unexpected server entry IP address")
		}

		if isExchanged {
			if serverEntry.LocalSource != protocol.SERVER_ENTRY_SOURCE_EXCHANGED {
				t.Fatalf("unexpected non-exchanged server entry source")
			}
		} else {
			if serverEntry.LocalSource == protocol.SERVER_ENTRY_SOURCE_EXCHANGED {
				t.Fatalf("unexpected exchanged server entry source")
			}
		}

		dialParams, err := GetDialParameters(config, serverEntry.IpAddress, networkID)
		if err != nil {
			t.Fatalf("GetDialParameters failed: %s", err)
		}

		if tunnelProtocol == "" {
			if dialParams != nil {
				t.Fatalf("unexpected non-nil dial parameters")
			}
		} else if isExchanged {
			if !dialParams.IsExchanged {
				t.Fatalf("unexpected non-exchanged dial parameters")
			}
			if dialParams.TunnelProtocol != tunnelProtocol {
				t.Fatalf("unexpected exchanged dial parameters tunnel protocol")
			}
		} else {
			if dialParams.IsExchanged {
				t.Fatalf("unexpected exchanged dial parameters")
			}
			if dialParams.TunnelProtocol != tunnelProtocol {
				t.Fatalf("unexpected dial parameters tunnel protocol")
			}
		}
	}

	// Test: pave only an unsigned server entry; export should fail

	paveServerEntry(serverEntry0, tunnelProtocol0)

	payload := ExportExchangePayload(config)
	if payload != "" {
		t.Fatalf("ExportExchangePayload unexpectedly succeeded")
	}

	// Test: pave two signed server entries; serverEntry2 is the affinity server
	// entry and should be the exported server entry

	paveServerEntry(serverEntry1, tunnelProtocol1)
	paveServerEntry(serverEntry2, tunnelProtocol2)

	payload = ExportExchangePayload(config)
	if payload == "" {
		t.Fatalf("ExportExchangePayload failed")
	}

	// Test: import; serverEntry2 should be imported

	// Before importing the exported payload, move serverEntry1 to the affinity
	// position. After the import, we expect serverEntry2 to be at the affinity
	// position and its dial parameters to be IsExchanged and and have the
	// exchanged tunnel protocol.

	err = PromoteServerEntry(config, serverEntry1["ipAddress"].(string))
	if err != nil {
		t.Fatalf("PromoteServerEntry failed: %s", err)
	}

	checkFirstServerEntry(serverEntry1, tunnelProtocol1, false)

	if !ImportExchangePayload(config, payload) {
		t.Fatalf("ImportExchangePayload failed")
	}

	checkFirstServerEntry(serverEntry2, tunnelProtocol2, true)

	// Test: nil exchanged dial parameters case

	paveServerEntry(serverEntry3, tunnelProtocol3)

	payload = ExportExchangePayload(config)
	if payload == "" {
		t.Fatalf("ExportExchangePayload failed")
	}

	err = PromoteServerEntry(config, serverEntry1["ipAddress"].(string))
	if err != nil {
		t.Fatalf("PromoteServerEntry failed: %s", err)
	}

	checkFirstServerEntry(serverEntry1, tunnelProtocol1, false)

	if !ImportExchangePayload(config, payload) {
		t.Fatalf("ImportExchangePayload failed")
	}

	checkFirstServerEntry(serverEntry3, tunnelProtocol3, true)
}
