//go:build PSIPHON_RUN_PACKET_MANIPULATOR_TEST
// +build PSIPHON_RUN_PACKET_MANIPULATOR_TEST

/*
 * Copyright (c) 2020, Psiphon Inc.
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

package packetman

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
)

func TestPacketManipulatorIPv4(t *testing.T) {
	testPacketManipulator(false, t)
}

func TestPacketManipulatorIPv6(t *testing.T) {
	testPacketManipulator(true, t)
}

func testPacketManipulator(useIPv6 bool, t *testing.T) {

	// Test: run a Manipulator in front of a web server; make an HTTP request;
	// the expected transformation spec should be executed (as reported by
	// GetAppliedSpecName) and the request must succeed.

	ipv4, ipv6, err := common.GetRoutableInterfaceIPAddresses()
	if err != nil {
		t.Fatalf("GetRoutableInterfaceIPAddressesfailed: %v", err)
	}

	network := "tcp4"
	address := net.JoinHostPort(ipv4.String(), "0")
	if useIPv6 {
		if ipv6 == nil {
			t.Skipf("test unsupported: no IP address")
		}
		network = "tcp6"
		address = net.JoinHostPort(ipv6.String(), "0")
	}

	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer listener.Close()

	hostStr, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort failed: %s", err.Error())
	}
	listenerPort, _ := strconv.Atoi(portStr)

	// [["TCP-flags S"]] replaces the original SYN-ACK packet with a single
	// SYN packet, implementing TCP simultaneous open.

	testSpecName := "test-spec"
	extraDataValue := "extra-data"
	config := &Config{
		Logger:        testutils.NewTestLogger(),
		ProtocolPorts: []int{listenerPort},
		Specs:         []*Spec{{Name: testSpecName, PacketSpecs: [][]string{{"TCP-flags S"}}}},
		SelectSpecName: func(protocolPort int, _ net.IP) (string, interface{}) {
			if protocolPort == listenerPort {
				return testSpecName, extraDataValue
			}
			return "", nil
		},
		QueueNumber: 1,
	}

	m, err := NewManipulator(config)
	if err != nil {
		t.Fatalf("NewManipulator failed: %v", err)
	}

	err = m.Start()
	if err != nil {
		t.Fatalf("Manipulator.Start failed: %v", err)
	}
	defer m.Stop()

	go func() {
		serveMux := http.NewServeMux()
		serveMux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, "test-response\n")
		})

		server := &http.Server{
			Handler: serveMux,
			ConnState: func(conn net.Conn, state http.ConnState) {
				if state == http.StateNew {
					localAddr := conn.LocalAddr().(*net.TCPAddr)
					remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
					specName, extraData, err := m.GetAppliedSpecName(localAddr, remoteAddr)
					if err != nil {
						t.Fatalf("GetAppliedSpecName failed: %v", err)
					}
					if specName != testSpecName {
						t.Fatalf("unexpected spec name: %s", specName)
					}
					extraDataStr, ok := extraData.(string)
					if !ok || extraDataStr != extraDataValue {
						t.Fatalf("unexpected extra data value: %v", extraData)
					}
				}
			},
		}

		server.Serve(listener)
	}()

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	response, err := httpClient.Get(fmt.Sprintf("http://%s:%s", hostStr, portStr))
	if err != nil {
		t.Fatalf("http.Get failed: %v", err)
	}
	defer response.Body.Close()
	_, err = ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("ioutil.ReadAll failed: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response code: %d", response.StatusCode)
	}
}
