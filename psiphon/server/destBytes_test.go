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

package server

import (
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func TestDestBytes(t *testing.T) {
	err := runTestDestBytes()
	if err != nil {
		t.Error(errors.Trace(err).Error())
	}
}

func runTestDestBytes() error {

	var logsMutex sync.Mutex
	var asnDestBytesLogs []map[string]interface{}
	var domainDestBytesLogs []map[string]interface{}

	// Discard logs, skipping InitLogging. Force disable useProtobufLogging,
	// which would otherwise require the udsipc.Reader/handler scheme in
	// server_test. Both asn_dest_bytes and domain_dest_bytes contents are
	// checked in server_test in PSIPHON_RUN_PROTOBUF_LOGGING_TEST mode.

	logWriter := log.Logger.Out
	protobufLogging := useProtobufLogging
	defer func() {
		log.Logger.Out = logWriter
		useProtobufLogging = protobufLogging
	}()
	log.Logger.Out = io.Discard

	logCallback := func(log []byte) {

		logFields := make(map[string]interface{})
		err := json.Unmarshal(log, &logFields)
		if err != nil {
			panic(err.Error())
		}

		logsMutex.Lock()
		defer logsMutex.Unlock()

		switch logFields["event_name"].(string) {
		case "asn_dest_bytes":
			asnDestBytesLogs = append(asnDestBytesLogs, logFields)
		case "domain_dest_bytes":
			domainDestBytesLogs = append(domainDestBytesLogs, logFields)
		}
	}

	setLogCallback(logCallback)
	defer setLogCallback(nil)

	const logPeriod = 250 * time.Millisecond

	destBytesLogger := newDestBytesLogger(&SupportServices{
		Config: &Config{
			destinationBytesPeriod: logPeriod,
		},
	})

	err := destBytesLogger.Start()
	if err != nil {
		return errors.Trace(err)
	}
	defer destBytesLogger.Stop()

	destASNs := []string{"00001", "00002"}
	destDomains := []string{"example.com", "example.org"}
	clientRegions := []string{"R1", "R2"}
	clientASNs := []string{"00003", "00004"}
	clientPlatformPrefixes := []string{"iOS", "Android"}
	sponsorIDs := []string{prng.HexString(SPONSOR_ID_LENGTH)}
	bytesTCP := int64(2048)
	bytesUDP := int64(1024)
	eventCount := 10

	addBytes := func() {
		for i := 0; i < eventCount; i++ {
			for _, clientRegion := range clientRegions {
				for _, clientASN := range clientASNs {

					geoIPData := GeoIPData{
						Country: clientRegion,
						ASN:     clientASN,
					}

					for _, clientPlatformPrefix := range clientPlatformPrefixes {

						clientPlatform := clientPlatformPrefix + prng.DefaultPRNG().HexString(4)

						apiParams := common.APIParameters{
							"client_platform": clientPlatform,
							"sponsor_id":      sponsorIDs[0],
						}

						for _, destASN := range destASNs {
							destBytesLogger.AddASNBytes(destASN, geoIPData, apiParams, bytesTCP, bytesUDP)
						}

						for _, destDomain := range destDomains {
							destBytesLogger.AddDomainBytes(destDomain, geoIPData, apiParams, bytesTCP, bytesUDP)
						}

					}
				}
			}
		}
	}

	checkLogs := func() error {

		logsMutex.Lock()
		defer logsMutex.Unlock()

		for i, logs := range [][]map[string]interface{}{asnDestBytesLogs, domainDestBytesLogs} {

			destCount := len(destASNs)
			if i != 0 {
				destCount = len(destDomains)
			}
			if len(logs) !=
				destCount*len(clientRegions)*len(clientASNs)*len(clientPlatformPrefixes)*len(sponsorIDs) {

				return errors.Tracef("unexpected log count: %d", len(logs))
			}

			loggedDestASNs := make(map[string]struct{})
			loggedDestDomains := make(map[string]struct{})
			loggedClientRegions := make(map[string]struct{})
			loggedClientASNs := make(map[string]struct{})
			loggedClientPlatforms := make(map[string]struct{})
			loggedSponsorIDs := make(map[string]struct{})

			sumBytesTCP := int64(0)
			sumBytesUDP := int64(0)
			sumBytes := int64(0)

			for _, logFields := range logs {
				if i == 0 {
					loggedDestASNs[logFields["asn"].(string)] = struct{}{}
				} else {
					loggedDestDomains[logFields["domain"].(string)] = struct{}{}
				}
				loggedClientRegions[logFields["client_region"].(string)] = struct{}{}
				loggedClientASNs[logFields["client_asn"].(string)] = struct{}{}
				loggedClientPlatforms[logFields["client_platform"].(string)] = struct{}{}
				loggedSponsorIDs[logFields["sponsor_id"].(string)] = struct{}{}
				sumBytesTCP += int64(logFields["bytes_tcp"].(float64))
				sumBytesUDP += int64(logFields["bytes_udp"].(float64))
				sumBytes += int64(logFields["bytes"].(float64))
			}

			checkFields := func(logged map[string]struct{}, expected []string) error {
				if len(logged) != len(expected) {
					return errors.Tracef("unexpected length: %d", len(logged))
				}
				for _, key := range expected {
					if _, ok := logged[key]; !ok {
						return errors.Tracef("missing %v", key)
					}
				}
				return nil
			}

			if i == 0 {
				err := checkFields(loggedDestASNs, destASNs)
				if err != nil {
					return errors.Trace(err)
				}
			} else {
				err = checkFields(loggedDestDomains, destDomains)
				if err != nil {
					return errors.Trace(err)
				}
			}
			err := checkFields(loggedClientRegions, clientRegions)
			if err != nil {
				return errors.Trace(err)
			}
			err = checkFields(loggedClientASNs, clientASNs)
			if err != nil {
				return errors.Trace(err)
			}
			err = checkFields(loggedClientPlatforms, clientPlatformPrefixes)
			if err != nil {
				return errors.Trace(err)
			}
			err = checkFields(loggedSponsorIDs, sponsorIDs)
			if err != nil {
				return errors.Trace(err)
			}

			if sumBytesTCP != int64(len(logs)*eventCount)*bytesTCP {
				return errors.Tracef("unexpected TCP bytes: %d", sumBytesTCP)
			}
			if sumBytesUDP != int64(len(logs)*eventCount)*bytesUDP {
				return errors.Tracef("unexpected UDP bytes: %d", sumBytesUDP)
			}
			if sumBytes != int64(len(logs)*eventCount)*(bytesTCP+bytesUDP) {
				return errors.Tracef("unexpected bytes: %d", sumBytes)
			}
		}

		asnDestBytesLogs = nil
		domainDestBytesLogs = nil

		return nil
	}

	for i := 0; i < 3; i++ {

		addBytes()

		time.Sleep(logPeriod * 2)

		err := checkLogs()
		if err != nil {
			return errors.Trace(err)
		}
	}

	addBytes()

	destBytesLogger.Stop()

	err = checkLogs()
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}
