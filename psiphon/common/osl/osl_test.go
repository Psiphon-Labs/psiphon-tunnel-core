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

package osl

import (
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

func TestOSL(t *testing.T) {

	configJSONTemplate := `
{
  "Schemes" : [
    {
      "Epoch" : "%s",

      "Regions" : ["US", "CA"],

      "PropagationChannelIDs" : ["2995DB0C968C59C4F23E87988D9C0D41", "E742C25A6D8BA8C17F37E725FA628569"],

      "MasterKey" : "wFuSbqU/pJ/35vRmoM8T9ys1PgDa8uzJps1Y+FNKa5U=",

      "SeedSpecs" : [
        {
          "Description": "spec1",
          "ID" : "IXHWfVgWFkEKvgqsjmnJuN3FpaGuCzQMETya+DSQvsk=",
          "UpstreamSubnets" : ["192.168.0.0/16", "172.16.0.0/12"],
          "Targets" :
          {
              "BytesRead" : 1,
              "BytesWritten" : 1,
              "PortForwardDurationNanoseconds" : 1
          }
        },
        {
          "Description": "spec2",
          "ID" : "qvpIcORLE2Pi5TZmqRtVkEp+OKov0MhfsYPLNV7FYtI=",
          "UpstreamSubnets" : ["192.168.0.0/16", "10.0.0.0/8"],
          "Targets" :
          {
              "BytesRead" : 10,
              "BytesWritten" : 10,
              "PortForwardDurationNanoseconds" : 10
          }
        },
        {
          "Description": "spec3",
          "ID" : "ts5LInjFHbVKX+/C5/bSJqUh+cLT5kJy92TZGLvAtPU=",
          "UpstreamSubnets" : ["100.64.0.0/10"],
          "Targets" :
          {
              "BytesRead" : 100,
              "BytesWritten" : 100,
              "PortForwardDurationNanoseconds" : 100
          }
        }
      ],

      "SeedSpecThreshold" : 2,

      "SeedPeriodNanoseconds" : 1000000,

      "SeedPeriodKeySplits": [
        {
          "Total": 10,
          "Threshold": 5
        },
        {
          "Total": 10,
          "Threshold": 5
        }
      ]
    },
    {
      "Epoch" : "%s",

      "Regions" : ["US", "CA"],

      "PropagationChannelIDs" : ["36F1CF2DF1250BF0C7BA0629CE3DC657"],

      "MasterKey" : "fcyQy8JSxLXHt/Iom9Qj9wMnSjrsccTiiSPEsJicet4=",

      "SeedSpecs" : [
        {
          "Description": "spec1",
          "ID" : "NXY0/4lqMxx5XIszIhMbwHobH/qb2Gl0Bw/OGndc1vM=",
          "UpstreamSubnets" : ["192.168.0.0/16", "172.16.0.0/12"],
          "Targets" :
          {
              "BytesRead" : 1,
              "BytesWritten" : 1,
              "PortForwardDurationNanoseconds" : 1
          }
        },
        {
          "Description": "spec2",
          "ID" : "o78G6muv3idtbQKXoU05tF6gTlQj1LHmNe0eUWkZGxs=",
          "UpstreamSubnets" : ["192.168.0.0/16", "10.0.0.0/8"],
          "Targets" :
          {
              "BytesRead" : 10,
              "BytesWritten" : 10,
              "PortForwardDurationNanoseconds" : 10
          }
        },
        {
          "Description": "spec3",
          "ID" : "1DlAvJYpoSEfcqMXYBV7bDEtYu3LCQO39ISD5tmi8Uo=",
          "UpstreamSubnets" : ["100.64.0.0/10"],
          "Targets" :
          {
              "BytesRead" : 0,
              "BytesWritten" : 0,
              "PortForwardDurationNanoseconds" : 0
          }
        }
      ],

      "SeedSpecThreshold" : 2,

      "SeedPeriodNanoseconds" : 1000000,

      "SeedPeriodKeySplits": [
        {
          "Total": 100,
          "Threshold": 25
        }
      ]
    }
  ]
}
`
	now := time.Now().UTC()
	epoch := now.Truncate(1 * time.Millisecond)
	epochStr := epoch.Format(time.RFC3339Nano)
	configJSON := fmt.Sprintf(configJSONTemplate, epochStr, epochStr)

	// The first scheme requires sufficient activity within 5/10 1 millisecond
	// periods and 5/10 10 millisecond longer periods. The second scheme requires
	// sufficient activity within 25/100 1 millisecond periods.

	config, err := LoadConfig([]byte(configJSON))
	if err != nil {
		t.Fatalf("LoadConfig failed: %s", err)
	}

	t.Run("ineligible client, sufficient transfer", func(t *testing.T) {

		clientSeedState := config.NewClientSeedState("US", "C5E8D2EDFD093B50D8D65CF59D0263CA", nil)

		seedPortForward := clientSeedState.NewClientSeedPortForward(net.ParseIP("192.168.0.1"))

		if seedPortForward != nil {
			t.Fatalf("expected nil client seed port forward")
		}
	})

	// This clientSeedState is used across multiple tests.
	signalIssueSLOKs := make(chan struct{}, 1)
	clientSeedState := config.NewClientSeedState("US", "2995DB0C968C59C4F23E87988D9C0D41", signalIssueSLOKs)

	t.Run("eligible client, no transfer", func(t *testing.T) {

		if len(clientSeedState.GetSeedPayload().SLOKs) != 0 {
			t.Fatalf("expected 0 SLOKs, got %d", len(clientSeedState.GetSeedPayload().SLOKs))
		}
	})

	t.Run("eligible client, insufficient transfer", func(t *testing.T) {

		clientSeedState.NewClientSeedPortForward(net.ParseIP("10.0.0.1")).UpdateProgress(5, 5, 5)

		if len(clientSeedState.GetSeedPayload().SLOKs) != 0 {
			t.Fatalf("expected 0 SLOKs, got %d", len(clientSeedState.GetSeedPayload().SLOKs))
		}
	})

	rolloverToNextSLOKTime := func() {
		// Rollover to the next SLOK time, so accrued data transfer will be reset.
		now := time.Now().UTC()
		time.Sleep(now.Add(1 * time.Millisecond).Truncate(1 * time.Millisecond).Sub(now))
	}

	t.Run("eligible client, insufficient transfer after rollover", func(t *testing.T) {

		rolloverToNextSLOKTime()

		clientSeedState.NewClientSeedPortForward(net.ParseIP("10.0.0.1")).UpdateProgress(5, 5, 5)

		if len(clientSeedState.GetSeedPayload().SLOKs) != 0 {
			t.Fatalf("expected 0 SLOKs, got %d", len(clientSeedState.GetSeedPayload().SLOKs))
		}
	})

	t.Run("eligible client, sufficient transfer, one port forward", func(t *testing.T) {

		rolloverToNextSLOKTime()

		clientSeedPortForward := clientSeedState.NewClientSeedPortForward(net.ParseIP("10.0.0.1"))

		clientSeedPortForward.UpdateProgress(5, 5, 5)

		clientSeedPortForward.UpdateProgress(5, 5, 5)

		select {
		case <-signalIssueSLOKs:
		default:
			t.Fatalf("expected issue SLOKs signal")
		}

		if len(clientSeedState.GetSeedPayload().SLOKs) != 1 {
			t.Fatalf("expected 1 SLOKs, got %d", len(clientSeedState.GetSeedPayload().SLOKs))
		}
	})

	t.Run("eligible client, sufficient transfer, multiple port forwards", func(t *testing.T) {

		rolloverToNextSLOKTime()

		clientSeedState.NewClientSeedPortForward(net.ParseIP("10.0.0.1")).UpdateProgress(5, 5, 5)

		clientSeedState.NewClientSeedPortForward(net.ParseIP("10.0.0.1")).UpdateProgress(5, 5, 5)

		select {
		case <-signalIssueSLOKs:
		default:
			t.Fatalf("expected issue SLOKs signal")
		}

		// Expect 2 SLOKS: 1 new, and 1 remaining in payload.
		if len(clientSeedState.GetSeedPayload().SLOKs) != 2 {
			t.Fatalf("expected 2 SLOKs, got %d", len(clientSeedState.GetSeedPayload().SLOKs))
		}
	})

	t.Run("eligible client, sufficient transfer multiple SLOKs", func(t *testing.T) {

		rolloverToNextSLOKTime()

		clientSeedState.NewClientSeedPortForward(net.ParseIP("192.168.0.1")).UpdateProgress(5, 5, 5)

		clientSeedState.NewClientSeedPortForward(net.ParseIP("10.0.0.1")).UpdateProgress(5, 5, 5)

		select {
		case <-signalIssueSLOKs:
		default:
			t.Fatalf("expected issue SLOKs signal")
		}

		// Expect 4 SLOKS: 2 new, and 2 remaining in payload.
		if len(clientSeedState.GetSeedPayload().SLOKs) != 4 {
			t.Fatalf("expected 4 SLOKs, got %d", len(clientSeedState.GetSeedPayload().SLOKs))
		}
	})

	t.Run("clear payload", func(t *testing.T) {
		clientSeedState.ClearSeedPayload()

		if len(clientSeedState.GetSeedPayload().SLOKs) != 0 {
			t.Fatalf("expected 0 SLOKs, got %d", len(clientSeedState.GetSeedPayload().SLOKs))
		}
	})

	t.Run("no transfer required", func(t *testing.T) {

		rolloverToNextSLOKTime()

		clientSeedState := config.NewClientSeedState("US", "36F1CF2DF1250BF0C7BA0629CE3DC657", nil)

		if len(clientSeedState.GetSeedPayload().SLOKs) != 1 {
			t.Fatalf("expected 1 SLOKs, got %d", len(clientSeedState.GetSeedPayload().SLOKs))
		}
	})

	signingPublicKey, signingPrivateKey, err := common.GenerateAuthenticatedDataPackageKeys()
	if err != nil {
		t.Fatalf("GenerateAuthenticatedDataPackageKeys failed: %s", err)
	}

	files := make(map[string][]byte)

	t.Run("pave OSLs", func(t *testing.T) {

		// Pave sufficient OSLs to cover simulated elapsed time of all test cases.
		endTime := epoch.Add(1000 * time.Millisecond)

		// Dummy server entry payloads will be the OSL ID, which the following
		// tests use to verify that the correct OSL file decrypts successfully.
		paveServerEntries := make([]map[time.Time]string, len(config.Schemes))
		for schemeIndex, scheme := range config.Schemes {

			paveServerEntries[schemeIndex] = make(map[time.Time]string)

			slokTimePeriodsPerOSL := 1
			for _, keySplit := range scheme.SeedPeriodKeySplits {
				slokTimePeriodsPerOSL *= keySplit.Total
			}

			oslTime := scheme.epoch
			for oslTime.Before(endTime) {
				firstSLOKRef := &slokReference{
					SeedSpecID: string(scheme.SeedSpecs[0].ID),
					Time:       oslTime,
				}
				firstSLOK := deriveSLOK(scheme, firstSLOKRef)
				oslID := firstSLOK.ID
				paveServerEntries[schemeIndex][oslTime] =
					base64.StdEncoding.EncodeToString(oslID)

				oslTime = oslTime.Add(
					time.Duration(
						int64(slokTimePeriodsPerOSL) * scheme.SeedPeriodNanoseconds))
			}
		}

		paveFiles, err := config.Pave(
			endTime,
			signingPublicKey,
			signingPrivateKey,
			paveServerEntries)
		if err != nil {
			t.Fatalf("Pave failed: %s", err)
		}

		// Check that the paved file name matches the name the client will look for.
		if len(paveFiles) < 1 || paveFiles[len(paveFiles)-1].Name != GetOSLRegistryURL("") {
			t.Fatalf("invalid registry pave file")
		}

		for _, paveFile := range paveFiles {
			files[paveFile.Name] = paveFile.Contents
		}
	})

	if len(files) == 0 {
		// Previous subtest failed. Following tests cannot be completed, so abort.
		t.Fatalf("pave failed")
	}

	// To ensure SLOKs are issued at precise time periods, the following tests
	// bypass ClientSeedState and derive SLOKs directly.

	expandRanges := func(ranges ...[2]int) []int {
		a := make([]int, 0)
		for _, r := range ranges {
			for n := r[0]; n <= r[1]; n++ {
				a = append(a, n)
			}
		}
		return a
	}

	singleSplitPropagationChannelID := "36F1CF2DF1250BF0C7BA0629CE3DC657"
	singleSplitScheme := config.Schemes[1]

	doubleSplitPropagationChannelID := "2995DB0C968C59C4F23E87988D9C0D41"
	doubleSplitScheme := config.Schemes[0]

	keySplitTestCases := []struct {
		description              string
		propagationChannelID     string
		scheme                   *Scheme
		issueSLOKTimePeriods     []int
		issueSLOKSeedSpecIndexes []int
		expectedOSLCount         int
	}{
		{
			"single split scheme: insufficient SLOK periods",
			singleSplitPropagationChannelID,
			singleSplitScheme,
			expandRanges([2]int{0, 23}),
			[]int{0, 1},
			0,
		},
		{
			"single split scheme: insufficient SLOK seed specs",
			singleSplitPropagationChannelID,
			singleSplitScheme,
			expandRanges([2]int{0, 23}),
			[]int{0},
			0,
		},
		{
			"single split scheme: sufficient SLOKs",
			singleSplitPropagationChannelID,
			singleSplitScheme,
			expandRanges([2]int{0, 24}),
			[]int{0, 1},
			1,
		},
		{
			"single split scheme: sufficient SLOKs (alternative seed specs)",
			singleSplitPropagationChannelID,
			singleSplitScheme,
			expandRanges([2]int{0, 24}),
			[]int{1, 2},
			1,
		},
		{
			"single split scheme: more than sufficient SLOKs",
			singleSplitPropagationChannelID,
			singleSplitScheme,
			expandRanges([2]int{0, 49}),
			[]int{0, 1},
			1,
		},
		{
			"double split scheme: insufficient SLOK periods",
			doubleSplitPropagationChannelID,
			doubleSplitScheme,
			expandRanges([2]int{0, 4}, [2]int{10, 14}, [2]int{20, 24}, [2]int{30, 34}, [2]int{40, 43}),
			[]int{0, 1},
			0,
		},
		{
			"double split scheme: insufficient SLOK period spread",
			doubleSplitPropagationChannelID,
			doubleSplitScheme,
			expandRanges([2]int{0, 25}),
			[]int{0, 1},
			0,
		},
		{
			"double split scheme: insufficient SLOK seed specs",
			doubleSplitPropagationChannelID,
			doubleSplitScheme,
			expandRanges([2]int{0, 4}, [2]int{10, 14}, [2]int{20, 24}, [2]int{30, 34}, [2]int{40, 44}),
			[]int{0},
			0,
		},
		{
			"double split scheme: sufficient SLOKs",
			doubleSplitPropagationChannelID,
			doubleSplitScheme,
			expandRanges([2]int{0, 4}, [2]int{10, 14}, [2]int{20, 24}, [2]int{30, 34}, [2]int{40, 44}),
			[]int{0, 1},
			1,
		},
		{
			"double split scheme: sufficient SLOKs (alternative seed specs)",
			doubleSplitPropagationChannelID,
			doubleSplitScheme,
			expandRanges([2]int{0, 4}, [2]int{10, 14}, [2]int{20, 24}, [2]int{30, 34}, [2]int{40, 44}),
			[]int{1, 2},
			1,
		},
	}

	for _, testCase := range keySplitTestCases {
		t.Run(testCase.description, func(t *testing.T) {

			slokMap := make(map[string][]byte)

			for _, timePeriod := range testCase.issueSLOKTimePeriods {
				for _, seedSpecIndex := range testCase.issueSLOKSeedSpecIndexes {

					slok := deriveSLOK(
						testCase.scheme,
						&slokReference{
							SeedSpecID: string(testCase.scheme.SeedSpecs[seedSpecIndex].ID),
							Time:       epoch.Add(time.Duration(timePeriod) * time.Millisecond),
						})

					slokMap[string(slok.ID)] = slok.Key

				}
			}

			t.Logf("SLOK count: %d", len(slokMap))

			slokLookup := func(slokID []byte) []byte {
				return slokMap[string(slokID)]
			}

			checkRegistryStartTime := time.Now()

			registry, _, err := UnpackRegistry(files[GetOSLRegistryURL("")], signingPublicKey)
			if err != nil {
				t.Fatalf("UnpackRegistry failed: %s", err)
			}

			t.Logf("registry size: %d", len(files[GetOSLRegistryURL("")]))
			t.Logf("registry OSL count: %d", len(registry.FileSpecs))

			oslIDs := registry.GetSeededOSLIDs(
				slokLookup,
				func(err error) {
					// Actual client will treat errors as warnings.
					t.Fatalf("GetSeededOSLIDs failed: %s", err)
				})

			t.Logf("check registry elapsed time: %s", time.Since(checkRegistryStartTime))

			if len(oslIDs) != testCase.expectedOSLCount {
				t.Fatalf("expected %d OSLs got %d", testCase.expectedOSLCount, len(oslIDs))
			}

			for _, oslID := range oslIDs {
				oslFileContents, ok := files[GetOSLFileURL("", oslID)]
				if !ok {
					t.Fatalf("unknown OSL file name")
				}

				plaintextOSL, err := registry.UnpackOSL(
					slokLookup, oslID, oslFileContents, signingPublicKey)
				if err != nil {
					t.Fatalf("DecryptOSL failed: %s", err)
				}

				// The decrypted OSL should contain its own ID.
				if plaintextOSL != base64.StdEncoding.EncodeToString(oslID) {
					t.Fatalf("unexpected OSL file contents")
				}
			}
		})
	}
}
