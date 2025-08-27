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

package server

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
)

func TestServerTacticsParametersCache(t *testing.T) {

	tacticsConfigJSONFormat := `
    {
      "RequestPublicKey" : "%s",
      "RequestPrivateKey" : "%s",
      "RequestObfuscatedKey" : "%s",
      "DefaultTactics" : {
        "TTL" : "60s",
        "Probability" : 1.0,
        "Parameters" : {
          "ConnectionWorkerPoolSize" : 1
        }
      },
      "FilteredTactics" : [
        {
          "Filter" : {
            "Regions": ["R1"]
          },
          "Tactics" : {
            "Parameters" : {
              "ConnectionWorkerPoolSize" : 2
            }
          }
        },
        {
          "Filter" : {
            "Regions": ["R2"],
            "ISPs": ["I2a"]
          },
          "Tactics" : {
            "Parameters" : {
              "ConnectionWorkerPoolSize" : 3
            }
          }
        },
        {
          "Filter" : {
            "Regions": ["R2"],
            "ISPs": ["I2b"]
          },
          "Tactics" : {
            "Parameters" : {
              "ConnectionWorkerPoolSize" : 4
            }
          }
        },
        {
          "Filter" : {
            "Regions": ["R2"],
            "ISPs": ["I2c"]
          },
          "Tactics" : {
            "Parameters" : {
              "ConnectionWorkerPoolSize" : 4
            }
          }
        },
        {
          "Filter" : {
            "Regions": ["R3"],
            "ASNs": ["31"]
          },
          "Tactics" : {
            "Parameters" : {
              "ConnectionWorkerPoolSize" : 5
            }
          }
        },
        {
          "Filter" : {
            "Regions": ["R3"],
            "ASNs": ["32"]
          },
          "Tactics" : {
            "Parameters" : {
              "ConnectionWorkerPoolSize" : 6
            }
          }
        },
        {
          "Filter" : {
            "Regions": ["R3"],
            "ASNs": ["33"]
          },
          "Tactics" : {
            "Parameters" : {
              "ConnectionWorkerPoolSize" : 6
            }
          }
        }
      ]
    }
    `

	tacticsRequestPublicKey, tacticsRequestPrivateKey, tacticsRequestObfuscatedKey, err :=
		tactics.GenerateKeys()
	if err != nil {
		t.Fatalf("error generating tactics keys: %s", err)
	}

	tacticsConfigJSON := fmt.Sprintf(
		tacticsConfigJSONFormat,
		tacticsRequestPublicKey, tacticsRequestPrivateKey, tacticsRequestObfuscatedKey)

	tacticsConfigFilename := filepath.Join(testDataDirName, "tactics_config.json")

	err = ioutil.WriteFile(tacticsConfigFilename, []byte(tacticsConfigJSON), 0600)
	if err != nil {
		t.Fatalf("error paving tactics config file: %s", err)
	}

	tacticsServer, err := tactics.NewServer(
		nil, nil, nil, tacticsConfigFilename, "", "", "")
	if err != nil {
		t.Fatalf("NewServer failed: %s", err)
	}

	support := &SupportServices{
		TacticsServer: tacticsServer,
	}
	support.ReplayCache = NewReplayCache(support)
	support.ServerTacticsParametersCache =
		NewServerTacticsParametersCache(support)

	keySplitTestCases := []struct {
		description                          string
		geoIPData                            GeoIPData
		expectedConnectionWorkerPoolSize     int
		expectedCacheSizeBefore              int
		expectedCacheSizeAfter               int
		expectedParameterReferencesSizeAfter int
	}{
		{
			"add new cache entry, default parameter",
			GeoIPData{Country: "R0", ISP: "I0", City: "C0"},
			1,
			0, 1, 1,
		},
		{
			"region already cached, region-only key",
			GeoIPData{Country: "R0", ISP: "I1", City: "C1"},
			1,
			1, 1, 1,
		},
		{
			"add new cache entry, filtered parameter",
			GeoIPData{Country: "R1", ISP: "I1a", City: "C1a"},
			2,
			1, 2, 2,
		},
		{
			"region already cached, region-only key",
			GeoIPData{Country: "R1", ISP: "I1a", City: "C1a"},
			2,
			2, 2, 2,
		},
		{
			"region already cached, region-only key",
			GeoIPData{Country: "R1", ISP: "I1b", City: "C1b"},
			2,
			2, 2, 2,
		},
		{
			"region already cached, region-only key",
			GeoIPData{Country: "R1", ISP: "I1b", City: "C1c"},
			2,
			2, 2, 2,
		},
		{
			"add new cache entry, filtered parameter, region/ISP key",
			GeoIPData{Country: "R2", ISP: "I2a", City: "C2a"},
			3,
			2, 3, 3,
		},
		{
			"region/ISP already cached",
			GeoIPData{Country: "R2", ISP: "I2a", City: "C2a"},
			3,
			3, 3, 3,
		},
		{
			"region/ISP already cached, city is ignored",
			GeoIPData{Country: "R2", ISP: "I2a", City: "C2b"},
			3,
			3, 3, 3,
		},
		{
			"add new cache entry, filtered parameter, region/ISP key",
			GeoIPData{Country: "R2", ISP: "I2b", City: "C2a"},
			4,
			3, 4, 4,
		},
		{
			"region/ISP already cached, city is ignored",
			GeoIPData{Country: "R2", ISP: "I2b", City: "C2b"},
			4,
			4, 4, 4,
		},
		{
			"add new cache entry, filtered parameter, region/ISP key, duplicate parameters",
			GeoIPData{Country: "R2", ISP: "I2c", City: "C2a"},
			4,
			4, 5, 4,
		},
		{
			"region already cached, region-only key",
			GeoIPData{Country: "R0", ASN: "0", City: "C1"},
			1,
			5, 5, 4,
		},
		{
			"region already cached, region-only key",
			GeoIPData{Country: "R1", ASN: "1", City: "C1a"},
			2,
			5, 5, 4,
		},
		{
			"add new cache entry, filtered parameter, region/ASN key",
			GeoIPData{Country: "R3", ASN: "31", City: "C2a"},
			5,
			5, 6, 5,
		},
		{
			"region/ASN already cached",
			GeoIPData{Country: "R3", ASN: "31", City: "C2a"},
			5,
			6, 6, 5,
		},
		{
			"region/ASN already cached, city is ignored",
			GeoIPData{Country: "R3", ASN: "31", City: "C2b"},
			5,
			6, 6, 5,
		},
		{
			"add new cache entry, filtered parameter, region/ASN key",
			GeoIPData{Country: "R3", ASN: "32", City: "C2a"},
			6,
			6, 7, 6,
		},
		{
			"region/ASN already cached, city is ignored",
			GeoIPData{Country: "R3", ASN: "32", City: "C2b"},
			6,
			7, 7, 6,
		},
		{
			"add new cache entry, filtered parameter, region/ASN key, duplicate parameters",
			GeoIPData{Country: "R3", ASN: "33", City: "C2a"},
			6,
			7, 8, 6,
		},
	}

	for _, testCase := range keySplitTestCases {
		t.Run(testCase.description, func(t *testing.T) {

			support.ServerTacticsParametersCache.mutex.Lock()
			cacheSize := support.ServerTacticsParametersCache.tacticsCache.Len()
			support.ServerTacticsParametersCache.mutex.Unlock()
			if cacheSize != testCase.expectedCacheSizeBefore {
				t.Fatalf("unexpected tacticsCache size before lookup: %d", cacheSize)
			}

			p, err := support.ServerTacticsParametersCache.Get(testCase.geoIPData)
			if err != nil {
				t.Fatalf("ServerTacticsParametersCache.Get failed: %d", err)
			}

			connectionWorkerPoolSize := p.Int(parameters.ConnectionWorkerPoolSize)
			if connectionWorkerPoolSize != testCase.expectedConnectionWorkerPoolSize {
				t.Fatalf("unexpected ConnectionWorkerPoolSize value: %d", connectionWorkerPoolSize)
			}

			support.ServerTacticsParametersCache.mutex.Lock()
			cacheSize = support.ServerTacticsParametersCache.tacticsCache.Len()
			support.ServerTacticsParametersCache.mutex.Unlock()
			if cacheSize != testCase.expectedCacheSizeAfter {
				t.Fatalf("unexpected cache size after lookup: %d", cacheSize)
			}

			support.ServerTacticsParametersCache.mutex.Lock()
			paramRefsSize := len(support.ServerTacticsParametersCache.parameterReferences)
			support.ServerTacticsParametersCache.mutex.Unlock()
			if paramRefsSize != testCase.expectedParameterReferencesSizeAfter {
				t.Fatalf("unexpected parameterReferences size after lookup: %d", paramRefsSize)
			}

		})
	}

	metrics := support.ServerTacticsParametersCache.GetMetrics()
	if metrics["server_tactics_max_cache_entries"].(int64) != 8 ||
		metrics["server_tactics_max_parameter_references"].(int64) != 6 ||
		metrics["server_tactics_cache_hit_count"].(int64) != 12 ||
		metrics["server_tactics_cache_miss_count"].(int64) != 8 {

		t.Fatalf("unexpected metrics: %v", metrics)
	}

	// Test: force eviction and check parameterReferences cleanup.

	for i := 0; i < TACTICS_CACHE_MAX_ENTRIES*2; i++ {
		_, err := support.ServerTacticsParametersCache.Get(
			GeoIPData{Country: "R2", ISP: fmt.Sprintf("I-%d", i), City: "C2a"})
		if err != nil {
			t.Fatalf("ServerTacticsParametersCache.Get failed: %d", err)
		}
	}

	support.ServerTacticsParametersCache.mutex.Lock()
	cacheSize := support.ServerTacticsParametersCache.tacticsCache.Len()
	paramRefsSize := len(support.ServerTacticsParametersCache.parameterReferences)
	support.ServerTacticsParametersCache.mutex.Unlock()

	if cacheSize != TACTICS_CACHE_MAX_ENTRIES {
		t.Fatalf("unexpected tacticsCache size before lookup: %d", cacheSize)

	}

	if paramRefsSize != 1 {
		t.Fatalf("unexpected parameterReferences size after lookup: %d", paramRefsSize)
	}
}
