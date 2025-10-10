/*
 * Copyright (c) 2022, Psiphon Inc.
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

package server

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

func TestTrafficRulesFilters(t *testing.T) {

	trafficRulesJSON := `
	{
      "DefaultRules" :  {
        "RateLimits" : {
          "WriteUnthrottledBytes": 1,
          "WriteBytesPerSecond": 2,
          "ReadUnthrottledBytes": 3,
          "ReadBytesPerSecond": 4,
          "UnthrottleFirstTunnelOnly": true
        },
        "AllowTCPPorts" : [5],
        "AllowUDPPorts" : [6]
      },
  
      "FilteredRules" : [
  
        {
          "Filter" : {
            "ProviderIDs" : ["H2"]
          },
          "Rules" : {
            "RateLimits" : {
              "WriteBytesPerSecond": 99,
              "ReadBytesPerSecond": 99
            }
          }
        },

        {
          "Filter" : {
            "ProviderIDs" : ["H1"],
            "Regions" : ["R2"],
            "HandshakeParameters" : {
                "client_version" : ["1"]
            }
          },
          "Rules" : {
            "RateLimits" : {
              "WriteBytesPerSecond": 7,
              "ReadBytesPerSecond": 8
            },
            "AllowTCPPorts" : [5,9],
            "AllowUDPPorts" : [6,10]
          }
        },

        {
          "Filter" : {
            "TunnelProtocols" : ["P2"],
            "Regions" : ["R3", "R4"],
            "HandshakeParameters" : {
                "client_version" : ["1", "2"]
            }
          },
          "ExceptFilter" : {
            "ISPs" : ["I2", "I3"],
            "HandshakeParameters" : {
                "client_version" : ["1"]
            }
          },
          "Rules" : {
            "RateLimits" : {
              "WriteBytesPerSecond": 11,
              "ReadBytesPerSecond": 12
            },
            "AllowTCPPorts" : [5,13],
            "AllowUDPPorts" : [6,14]
          }
        },

        {
          "Filter" : {
            "Regions" : ["R3", "R4"],
            "HandshakeParameters" : {
                "client_version" : ["1", "2"]
            }
          },
          "ExceptFilter" : {
            "ISPs" : ["I2", "I3"],
            "HandshakeParameters" : {
                "client_version" : ["1"]
            }
          },
          "Rules" : {
            "RateLimits" : {
              "WriteBytesPerSecond": 15,
              "ReadBytesPerSecond": 16
            },
            "AllowTCPPorts" : [5,17],
            "AllowUDPPorts" : [6,18]
          }
        },

        {
          "Filter" : {
            "Regions" : ["R5"],
            "MinClientVersion" : 30,
            "MaxClientVersion" : 40
          },
          "Rules" : {
            "RateLimits" : {
              "WriteBytesPerSecond": 17,
              "ReadBytesPerSecond": 18
            },
            "AllowTCPPorts" : [5,9],
            "AllowUDPPorts" : [6,10]
          }
        },

        {
          "Filter" : {
            "Regions" : ["R5"],
            "MinClientVersion" : 10,
            "MaxClientVersion" : 20
          },
          "Rules" : {
            "RateLimits" : {
              "WriteBytesPerSecond": 19,
              "ReadBytesPerSecond": 20
            },
            "AllowTCPPorts" : [7,11],
            "AllowUDPPorts" : [8,12]
          }
        }

      ]
    }
	`

	file, err := ioutil.TempFile("", "trafficRules.config")
	if err != nil {
		t.Fatalf("TempFile create failed: %s", err)
	}
	_, err = file.Write([]byte(trafficRulesJSON))
	if err != nil {
		t.Fatalf("TempFile write failed: %s", err)
	}
	file.Close()
	configFileName := file.Name()
	defer os.Remove(configFileName)

	trafficRules, err := NewTrafficRulesSet(configFileName)
	if err != nil {
		t.Fatalf("NewTrafficRulesSet failed: %s", err)
	}

	err = trafficRules.Validate()
	if err != nil {
		t.Fatalf("TrafficRulesSet.Validate failed: %s", err)
	}

	makePortList := func(portsJSON string) common.PortList {
		var p common.PortList
		_ = json.Unmarshal([]byte(portsJSON), &p)
		return p
	}

	// should never get 1st filtered rule with different provider ID
	providerID := "H1"

	testCases := []struct {
		description                   string
		providerID                    string
		isFirstTunnelInSession        bool
		tunnelProtocol                string
		geoIPData                     GeoIPData
		state                         handshakeState
		expectedWriteUnthrottledBytes int64
		expectedWriteBytesPerSecond   int64
		expectedReadUnthrottledBytes  int64
		expectedReadBytesPerSecond    int64
		expectedAllowTCPPorts         common.PortList
		expectedAllowUDPPorts         common.PortList
	}{
		{
			"get defaults",
			providerID,
			true,
			"P1",
			GeoIPData{Country: "R1", ISP: "I1"},
			handshakeState{apiParams: map[string]interface{}{"client_version": "1"}, completed: true},
			1, 2, 3, 4, makePortList("[5]"), makePortList("[6]"),
		},

		{
			"get defaults for not first tunnel in session",
			providerID,
			false,
			"P1",
			GeoIPData{Country: "R1", ISP: "I1"},
			handshakeState{apiParams: map[string]interface{}{"client_version": "1"}, completed: true},
			0, 2, 0, 4, makePortList("[5]"), makePortList("[6]"),
		},

		{
			"get 2nd filtered rule (including provider ID)",
			providerID,
			true,
			"P1",
			GeoIPData{Country: "R2", ISP: "I1"},
			handshakeState{apiParams: map[string]interface{}{"client_version": "1"}, completed: true},
			1, 7, 3, 8, makePortList("[5,9]"), makePortList("[6,10]"),
		},

		{
			"don't get 2nd filtered rule with incomplete match",
			providerID,
			true,
			"P1",
			GeoIPData{Country: "R2", ISP: "I1"},
			handshakeState{apiParams: map[string]interface{}{"client_version": "2"}, completed: true},
			1, 2, 3, 4, makePortList("[5]"), makePortList("[6]"),
		},

		{
			"get 3rd filtered rule",
			providerID,
			true,
			"P2",
			GeoIPData{Country: "R3", ISP: "I1"},
			handshakeState{apiParams: map[string]interface{}{"client_version": "2"}, completed: true},
			1, 11, 3, 12, makePortList("[5,13]"), makePortList("[6,14]"),
		},

		{
			"get 3rd filtered rule with incomplete exception",
			providerID,
			true,
			"P2",
			GeoIPData{Country: "R3", ISP: "I2"},
			handshakeState{apiParams: map[string]interface{}{"client_version": "2"}, completed: true},
			1, 11, 3, 12, makePortList("[5,13]"), makePortList("[6,14]"),
		},

		{
			"don't get 3rd filtered rule due to exception",
			providerID,
			true,
			"P2",
			GeoIPData{Country: "R3", ISP: "I2"},
			handshakeState{apiParams: map[string]interface{}{"client_version": "1"}, completed: true},
			1, 2, 3, 4, makePortList("[5]"), makePortList("[6]"),
		},

		{
			"get 4th filtered rule",
			providerID,
			true,
			"P1",
			GeoIPData{Country: "R3", ISP: "I1"},
			handshakeState{apiParams: map[string]interface{}{"client_version": "1"}, completed: true},
			1, 15, 3, 16, makePortList("[5,17]"), makePortList("[6,18]"),
		},

		{
			"don't get 4th filtered rule due to exception",
			providerID,
			true,
			"P1",
			GeoIPData{Country: "R3", ISP: "I2"},
			handshakeState{apiParams: map[string]interface{}{"client_version": "1"}, completed: true},
			1, 2, 3, 4, makePortList("[5]"), makePortList("[6]"),
		},

		{
			"don't get 4th filtered rule due to Min/MaxClientVersion",
			providerID,
			true,
			"P1",
			GeoIPData{Country: "R3", ISP: "I2"},
			handshakeState{apiParams: map[string]interface{}{"client_version": "1"}, completed: true},
			1, 2, 3, 4, makePortList("[5]"), makePortList("[6]"),
		},

		{
			"match 2nd Min/MaxClientVersion filtered rule",
			providerID,
			true,
			"P1",
			GeoIPData{Country: "R5", ISP: "I1"},
			handshakeState{apiParams: map[string]interface{}{"client_version": "15"}, completed: true},
			1, 19, 3, 20, makePortList("[7,11]"), makePortList("[8,12]"),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {

			rules := trafficRules.GetTrafficRules(
				testCase.providerID,
				testCase.isFirstTunnelInSession,
				testCase.tunnelProtocol,
				testCase.geoIPData,
				testCase.state)

			if *rules.RateLimits.WriteUnthrottledBytes != testCase.expectedWriteUnthrottledBytes {
				t.Errorf("unexpected rules.RateLimits.WriteUnthrottledBytes: %v != %v",
					*rules.RateLimits.WriteUnthrottledBytes, testCase.expectedWriteUnthrottledBytes)
			}
			if *rules.RateLimits.WriteBytesPerSecond != testCase.expectedWriteBytesPerSecond {
				t.Errorf("unexpected rules.RateLimits.WriteBytesPerSecond: %v != %v",
					*rules.RateLimits.WriteBytesPerSecond, testCase.expectedWriteBytesPerSecond)
			}
			if *rules.RateLimits.ReadUnthrottledBytes != testCase.expectedReadUnthrottledBytes {
				t.Errorf("unexpected rules.RateLimits.ReadUnthrottledBytes: %v != %v",
					*rules.RateLimits.ReadUnthrottledBytes, testCase.expectedReadUnthrottledBytes)
			}
			if *rules.RateLimits.ReadBytesPerSecond != testCase.expectedReadBytesPerSecond {
				t.Errorf("unexpected rules.RateLimits.ReadBytesPerSecond: %v != %v",
					*rules.RateLimits.ReadBytesPerSecond, testCase.expectedReadBytesPerSecond)
			}
			if !reflect.DeepEqual(*rules.AllowTCPPorts, testCase.expectedAllowTCPPorts) {
				t.Errorf("unexpected rules.RateLimits.AllowTCPPorts: %v != %v",
					*rules.AllowTCPPorts, testCase.expectedAllowTCPPorts)
			}
			if !reflect.DeepEqual(*rules.AllowUDPPorts, testCase.expectedAllowUDPPorts) {
				t.Errorf("unexpected rules.RateLimits.AllowUDPPorts: %v != %v",
					*rules.AllowUDPPorts, testCase.expectedAllowUDPPorts)
			}
		})
	}
}
