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
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
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

      "ASNs" : ["1"],

      "PropagationChannelIDs" : ["2995DB0C968C59C4F23E87988D9C0D41", "E742C25A6D8BA8C17F37E725FA628569", "B4A780E67695595FA486E9B900EA7335"],

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

      "SeedPeriodNanoseconds" : 5000000,

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

      "ASNs" : ["1"],

      "PropagationChannelIDs" : ["36F1CF2DF1250BF0C7BA0629CE3DC657", "B4A780E67695595FA486E9B900EA7335"],

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

      "SeedPeriodNanoseconds" : 5000000,

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
	seedPeriod := 5 * time.Millisecond // "SeedPeriodNanoseconds" : 5000000
	now := time.Now().UTC()
	epoch := now.Add(-seedPeriod).Truncate(seedPeriod)
	epochStr := epoch.Format(time.RFC3339Nano)
	configJSON := fmt.Sprintf(configJSONTemplate, epochStr, epochStr)

	// The first scheme requires sufficient activity within 5/10 5 millisecond
	// periods and 5/10 50 millisecond longer periods. The second scheme requires
	// sufficient activity within 25/100 5 millisecond periods.

	config, err := LoadConfig([]byte(configJSON))
	if err != nil {
		t.Fatalf("LoadConfig failed: %s", err)
	}

	t.Run("ineligible client, sufficient transfer", func(t *testing.T) {

		clientSeedState := config.NewClientSeedState("1", "US", "C5E8D2EDFD093B50D8D65CF59D0263CA", nil)

		seedPortForward := clientSeedState.NewClientSeedPortForward(net.ParseIP("192.168.0.1"))

		if seedPortForward != nil {
			t.Fatalf("expected nil client seed port forward")
		}
	})

	// This clientSeedState is used across multiple tests.
	signalIssueSLOKs := make(chan struct{}, 1)
	clientSeedState := config.NewClientSeedState("1", "US", "2995DB0C968C59C4F23E87988D9C0D41", signalIssueSLOKs)

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
		time.Sleep(now.Add(seedPeriod).Truncate(seedPeriod).Sub(now))
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

	t.Run("eligible client, no transfer required", func(t *testing.T) {

		rolloverToNextSLOKTime()

		clientSeedState := config.NewClientSeedState("1", "US", "36F1CF2DF1250BF0C7BA0629CE3DC657", nil)

		if len(clientSeedState.GetSeedPayload().SLOKs) != 1 {
			t.Fatalf("expected 1 SLOKs, got %d", len(clientSeedState.GetSeedPayload().SLOKs))
		}
	})

	t.Run("ineligible client, no transfer required", func(t *testing.T) {

		rolloverToNextSLOKTime()

		// Client ASN does not match scheme.
		clientSeedState = config.NewClientSeedState("", "US", "36F1CF2DF1250BF0C7BA0629CE3DC657", nil)
		if len(clientSeedState.GetSeedPayload().SLOKs) != 0 {
			t.Fatalf("expected 0 SLOKs, got %d", len(clientSeedState.GetSeedPayload().SLOKs))
		}

		// Client region does not match scheme.
		clientSeedState = config.NewClientSeedState("1", "", "36F1CF2DF1250BF0C7BA0629CE3DC657", nil)
		if len(clientSeedState.GetSeedPayload().SLOKs) != 0 {
			t.Fatalf("expected 0 SLOKs, got %d", len(clientSeedState.GetSeedPayload().SLOKs))
		}
	})

	t.Run("concurrent schemes", func(t *testing.T) {

		rolloverToNextSLOKTime()

		clientSeedState := config.NewClientSeedState("1", "US", "B4A780E67695595FA486E9B900EA7335", nil)

		clientSeedPortForward := clientSeedState.NewClientSeedPortForward(net.ParseIP("192.168.0.1"))

		clientSeedPortForward.UpdateProgress(10, 10, 10)

		if len(clientSeedState.GetSeedPayload().SLOKs) != 5 {
			t.Fatalf("expected 5 SLOKs, got %d", len(clientSeedState.GetSeedPayload().SLOKs))
		}
	})

	signingPublicKey, signingPrivateKey, err := common.GenerateAuthenticatedDataPackageKeys()
	if err != nil {
		t.Fatalf("GenerateAuthenticatedDataPackageKeys failed: %s", err)
	}

	pavedRegistries := make(map[string][]byte)
	pavedOSLFileContents := make(map[string]map[string][]byte)

	t.Run("pave OSLs", func(t *testing.T) {

		// Pave sufficient OSLs to cover simulated elapsed time of all test cases.
		endTime := epoch.Add(1000 * seedPeriod)

		// In actual deployment, paved files for each propagation channel ID
		// are dropped in distinct distribution sites.
		for _, propagationChannelID := range []string{
			"2995DB0C968C59C4F23E87988D9C0D41",
			"E742C25A6D8BA8C17F37E725FA628569",
			"36F1CF2DF1250BF0C7BA0629CE3DC657"} {

			// Dummy server entry payloads will be the OSL ID, which the following
			// tests use to verify that the correct OSL file decrypts successfully.
			paveServerEntries := make(map[string][]string)
			for _, scheme := range config.Schemes {

				oslDuration := scheme.GetOSLDuration()

				oslTime := scheme.epoch
				for oslTime.Before(endTime) {

					firstSLOKRef := &slokReference{
						PropagationChannelID: propagationChannelID,
						SeedSpecID:           string(scheme.SeedSpecs[0].ID),
						Time:                 oslTime,
					}
					firstSLOK := scheme.deriveSLOK(firstSLOKRef)
					oslID := firstSLOK.ID
					paveServerEntries[hex.EncodeToString(oslID)] =
						[]string{base64.StdEncoding.EncodeToString(oslID)}

					oslTime = oslTime.Add(oslDuration)
				}
			}

			// Note: these options are exercised in remoteServerList_test.go
			omitMD5SumsSchemes := []int{}
			omitEmptyOSLsSchemes := []int{}

			firstPaveFiles, err := config.Pave(
				time.Time{},
				endTime,
				propagationChannelID,
				signingPublicKey,
				signingPrivateKey,
				paveServerEntries,
				omitMD5SumsSchemes,
				omitEmptyOSLsSchemes,
				nil)
			if err != nil {
				t.Fatalf("Pave failed: %s", err)
			}

			offsetPaveFiles, err := config.Pave(
				epoch.Add(500*seedPeriod+seedPeriod/2),
				endTime,
				propagationChannelID,
				signingPublicKey,
				signingPrivateKey,
				paveServerEntries,
				omitMD5SumsSchemes,
				omitEmptyOSLsSchemes,
				nil)
			if err != nil {
				t.Fatalf("Pave failed: %s", err)
			}

			paveFiles, err := config.Pave(
				time.Time{},
				endTime,
				propagationChannelID,
				signingPublicKey,
				signingPrivateKey,
				paveServerEntries,
				omitMD5SumsSchemes,
				omitEmptyOSLsSchemes,
				nil)
			if err != nil {
				t.Fatalf("Pave failed: %s", err)
			}

			// Check that the paved file name matches the name the client will look for.

			if len(paveFiles) < 1 || paveFiles[len(paveFiles)-1].Name != GetOSLRegistryURL("") {
				t.Fatalf("invalid registry pave file")
			}

			// Check that the content of two paves is the same: all the crypto should be
			// deterministic.

			for index, paveFile := range paveFiles {
				if paveFile.Name != firstPaveFiles[index].Name {
					t.Fatalf("pave name mismatch")
				}
				if !bytes.Equal(paveFile.Contents, firstPaveFiles[index].Contents) {
					t.Fatalf("pave content mismatch")
				}
			}

			// Check that the output of a pave using an unaligned offset from epoch
			// produces a subset of OSLs with the same IDs and content: the OSL and
			// SLOK time slots must align.

			if len(offsetPaveFiles) >= len(paveFiles) {
				t.Fatalf("unexpected pave size")
			}

			for _, offsetPaveFile := range offsetPaveFiles {
				found := false
				for _, paveFile := range paveFiles {
					if offsetPaveFile.Name == paveFile.Name {
						if offsetPaveFile.Name != GetOSLRegistryURL("") &&
							!bytes.Equal(offsetPaveFile.Contents, paveFile.Contents) {
							t.Fatalf("pave content mismatch")
						}
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("pave name missing")
				}
			}

			// Use the paved content in the following tests.

			pavedRegistries[propagationChannelID] = paveFiles[len(paveFiles)-1].Contents

			pavedOSLFileContents[propagationChannelID] = make(map[string][]byte)
			for _, paveFile := range paveFiles[0:] {
				pavedOSLFileContents[propagationChannelID][paveFile.Name] = paveFile.Contents
			}
		}
	})

	if len(pavedRegistries) != 3 {
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

					slok := testCase.scheme.deriveSLOK(
						&slokReference{
							PropagationChannelID: testCase.propagationChannelID,
							SeedSpecID:           string(testCase.scheme.SeedSpecs[seedSpecIndex].ID),
							Time:                 epoch.Add(time.Duration(timePeriod) * seedPeriod),
						})

					slokMap[string(slok.ID)] = slok.Key

				}
			}

			startTime := time.Now()

			lookupSLOKs := func(slokID []byte) []byte {
				return slokMap[string(slokID)]
			}

			registryStreamer, err := NewRegistryStreamer(
				bytes.NewReader(pavedRegistries[testCase.propagationChannelID]),
				signingPublicKey,
				lookupSLOKs)
			if err != nil {
				t.Fatalf("NewRegistryStreamer failed: %s", err)
			}

			seededOSLCount := 0

			for {

				fileSpec, err := registryStreamer.Next()
				if err != nil {
					t.Fatalf("Next failed: %s", err)
				}

				if fileSpec == nil {
					break
				}

				seededOSLCount += 1

				oslFileContents, ok :=
					pavedOSLFileContents[testCase.propagationChannelID][GetOSLFileURL("", fileSpec.ID)]
				if !ok {
					t.Fatalf("unknown OSL file name")
				}

				payloadReader, err := NewOSLReader(
					bytes.NewReader(oslFileContents),
					fileSpec,
					lookupSLOKs,
					signingPublicKey)
				if err != nil {
					t.Fatalf("NewOSLReader failed: %s", err)
				}

				payload, err := ioutil.ReadAll(payloadReader)
				if err != nil {
					t.Fatalf("ReadAll failed: %s", err)
				}

				// The decrypted OSL should contain its own ID.
				if string(payload) != base64.StdEncoding.EncodeToString(fileSpec.ID) {
					t.Fatalf("unexpected OSL file contents")
				}
			}

			t.Logf("registry size: %d", len(pavedRegistries[testCase.propagationChannelID]))
			t.Logf("SLOK count: %d", len(slokMap))
			t.Logf("seeded OSL count: %d", seededOSLCount)
			t.Logf("elapsed time: %s", time.Since(startTime))

			if seededOSLCount != testCase.expectedOSLCount {
				t.Fatalf("expected %d OSLs got %d", testCase.expectedOSLCount, seededOSLCount)
			}
		})
	}
}
