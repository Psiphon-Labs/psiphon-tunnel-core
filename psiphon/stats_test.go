/*
 * Copyright (c) 2014, Psiphon Inc.
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
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/stretchr/testify/suite"
)

const (
	_SERVER_ID = "myserverid"
)

type StatsTestSuite struct {
	suite.Suite
	httpClient *http.Client
}

func TestStatsTestSuite(t *testing.T) {
	suite.Run(t, new(StatsTestSuite))
}

func (suite *StatsTestSuite) SetupTest() {
	Stats_Start()

	re := make(Regexps, 0)
	suite.httpClient = &http.Client{
		Transport: &http.Transport{
			Dial: makeStatsDialer(_SERVER_ID, &re),
		},
	}
}

func (suite *StatsTestSuite) TearDownTest() {
	suite.httpClient = nil
	Stats_Stop()
}

func makeStatsDialer(serverID string, regexps *Regexps) func(network, addr string) (conn net.Conn, err error) {
	return func(network, addr string) (conn net.Conn, err error) {
		var subConn net.Conn

		switch network {
		case "tcp", "tcp4", "tcp6":
			tcpAddr, err := net.ResolveTCPAddr(network, addr)
			if err != nil {
				return nil, err
			}
			subConn, err = net.DialTCP(network, nil, tcpAddr)
			if err != nil {
				return nil, err
			}
		default:
			err = errors.New("using an unsupported testing network type")
			return
		}

		conn = NewStatsConn(subConn, serverID, regexps)
		err = nil
		return
	}
}

func (suite *StatsTestSuite) Test_StartStop() {
	// Make sure Start and Stop calls don't crash
	Stats_Start()
	Stats_Start()
	Stats_Stop()
	Stats_Stop()
	Stats_Start()
	Stats_Stop()
}

func (suite *StatsTestSuite) Test_NextSendPeriod() {
	res1 := NextSendPeriod()
	suite.True(res1 > time.Duration(0), "duration should not be zero")

	res2 := NextSendPeriod()
	suite.NotEqual(res1, res2, "duration should have randomness difference between calls")
}

func (suite *StatsTestSuite) Test_StatsConn() {
	resp, err := suite.httpClient.Get("http://example.com/index.html")
	suite.Nil(err, "basic HTTP requests should succeed (1)")
	resp.Body.Close()

	resp, err = suite.httpClient.Get("http://example.org/index.html")
	suite.Nil(err, "basic HTTP requests should succeed (1)")
	resp.Body.Close()
}

func (suite *StatsTestSuite) Test_GetForServer() {
	payload := GetForServer(_SERVER_ID)
	suite.Nil(payload, "should get nil stats before any traffic (but not crash)")

	resp, err := suite.httpClient.Get("http://example.com/index.html")
	suite.Nil(err, "need successful http to proceed with tests")
	resp.Body.Close()

	// Make sure there aren't stats returned for a bad server ID
	payload = GetForServer("INVALID")
	suite.Nil(payload, "should get nil stats for invalid server ID")

	payload = GetForServer(_SERVER_ID)
	suite.NotNil(payload, "should receive valid payload for valid server ID")

	payloadJSON, err := json.Marshal(payload)
	var parsedJSON interface{}
	err = json.Unmarshal(payloadJSON, &parsedJSON)
	suite.Nil(err, "payload JSON should parse successfully")

	// After we retrieve the stats for a server, they should be cleared out of the tracked stats
	payload = GetForServer(_SERVER_ID)
	suite.Nil(payload, "after retrieving stats for a server, there should be no more stats (until more data goes through)")
}

func (suite *StatsTestSuite) Test_PutBack() {
	resp, err := suite.httpClient.Get("http://example.com/index.html")
	suite.Nil(err, "need successful http to proceed with tests")
	resp.Body.Close()

	payloadToPutBack := GetForServer(_SERVER_ID)
	suite.NotNil(payloadToPutBack, "should receive valid payload for valid server ID")

	payload := GetForServer(_SERVER_ID)
	suite.Nil(payload, "should not be any remaining stats after getting them")

	PutBack(_SERVER_ID, payloadToPutBack)
	// PutBack is asynchronous, so we'll need to wait a moment for it to do its thing
	<-time.After(100 * time.Millisecond)

	payload = GetForServer(_SERVER_ID)
	suite.NotNil(payload, "stats should be re-added after putting back")
	suite.Equal(payload, payloadToPutBack, "stats should be the same as after the first retrieval")
}

func (suite *StatsTestSuite) Test_MakeRegexps() {
	pageViewRegexes := []map[string]string{make(map[string]string)}
	pageViewRegexes[0]["regex"] = `(^http://[a-z0-9\.]*\.example\.[a-z\.]*)/.*`
	pageViewRegexes[0]["replace"] = "$1"

	httpsRequestRegexes := []map[string]string{make(map[string]string), make(map[string]string)}
	httpsRequestRegexes[0]["regex"] = `^[a-z0-9\.]*\.(example\.com)$`
	httpsRequestRegexes[0]["replace"] = "$1"
	httpsRequestRegexes[1]["regex"] = `^.*example\.org$`
	httpsRequestRegexes[1]["replace"] = "replacement"

	regexps := MakeRegexps(pageViewRegexes, httpsRequestRegexes)
	suite.NotNil(regexps, "should return a valid object")
	suite.Len(*regexps, 2, "should only have processed httpsRequestRegexes")

	//
	// Test some bad regexps
	//

	httpsRequestRegexes[0]["regex"] = ""
	httpsRequestRegexes[0]["replace"] = "$1"
	regexps = MakeRegexps(pageViewRegexes, httpsRequestRegexes)
	suite.NotNil(regexps, "should return a valid object")
	suite.Len(*regexps, 1, "should have discarded one regexp")

	httpsRequestRegexes[0]["regex"] = `^[a-z0-9\.]*\.(example\.com)$`
	httpsRequestRegexes[0]["replace"] = ""
	regexps = MakeRegexps(pageViewRegexes, httpsRequestRegexes)
	suite.NotNil(regexps, "should return a valid object")
	suite.Len(*regexps, 1, "should have discarded one regexp")

	httpsRequestRegexes[0]["regex"] = `^[a-z0-9\.]*\.(example\.com$` // missing closing paren
	httpsRequestRegexes[0]["replace"] = "$1"
	regexps = MakeRegexps(pageViewRegexes, httpsRequestRegexes)
	suite.NotNil(regexps, "should return a valid object")
	suite.Len(*regexps, 1, "should have discarded one regexp")
}

func (suite *StatsTestSuite) Test_Regex() {
	// We'll make a new client with actual regexps.
	pageViewRegexes := make([]map[string]string, 0)
	httpsRequestRegexes := []map[string]string{make(map[string]string), make(map[string]string)}
	httpsRequestRegexes[0]["regex"] = `^[a-z0-9\.]*\.(example\.com)$`
	httpsRequestRegexes[0]["replace"] = "$1"
	httpsRequestRegexes[1]["regex"] = `^.*example\.org$`
	httpsRequestRegexes[1]["replace"] = "replacement"
	regexps := MakeRegexps(pageViewRegexes, httpsRequestRegexes)

	suite.httpClient = &http.Client{
		Transport: &http.Transport{
			Dial: makeStatsDialer(_SERVER_ID, regexps),
		},
	}

	// No subdomain, so won't match regex
	resp, err := suite.httpClient.Get("http://example.com/index.html")
	suite.Nil(err)
	resp.Body.Close()

	// Will match the first regex
	resp, err = suite.httpClient.Get("http://www.example.com/index.html")
	suite.Nil(err)
	resp.Body.Close()

	// Will match the second regex
	resp, err = suite.httpClient.Get("http://example.org/index.html")
	suite.Nil(err)
	resp.Body.Close()

	payload := GetForServer(_SERVER_ID)
	suite.NotNil(payload, "should get stats because we made HTTP reqs")

	expectedHostnames := mapset.NewSet()
	expectedHostnames.Add("(OTHER)")
	expectedHostnames.Add("example.com")
	expectedHostnames.Add("replacement")

	hostnames := make([]interface{}, 0)
	for hostname := range payload.hostnameToStats {
		hostnames = append(hostnames, hostname)
	}

	actualHostnames := mapset.NewSetFromSlice(hostnames)

	suite.Equal(expectedHostnames, actualHostnames, "post-regex hostnames should be processed as expecteds")
}

func (suite *StatsTestSuite) Test_recordStat() {
	// The normal operation of this function will get exercised during the
	// other tests. Here we will quickly record more stats updates than the
	// channel capacity. The test is just that this function returns, and doesn't
	// crash or block forever.
	stat := statsUpdate{"test", "test", 1, 1}
	for i := 0; i < _CHANNEL_CAPACITY*2; i++ {
		recordStat(&stat)
	}
}
