/*
 * Copyright (c) 2015, Psiphon Inc.
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

package transferstats

import (
	"encoding/json"
	"errors"
	"fmt"
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

var nextServerID = 0

type StatsTestSuite struct {
	suite.Suite
	serverID   string
	httpClient *http.Client
}

func TestStatsTestSuite(t *testing.T) {
	suite.Run(t, new(StatsTestSuite))
}

func (suite *StatsTestSuite) SetupTest() {
	re := make(Regexps, 0)
	suite.serverID = fmt.Sprintf("%s-%d", _SERVER_ID, nextServerID)
	nextServerID++
	suite.httpClient = &http.Client{
		Transport: &http.Transport{
			Dial: makeStatsDialer(suite.serverID, &re),
		},
	}
}

func (suite *StatsTestSuite) TearDownTest() {
	suite.httpClient = nil
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

		conn = NewConn(subConn, serverID, regexps)
		err = nil
		return
	}
}

func (suite *StatsTestSuite) Test_StatsConn() {
	resp, err := suite.httpClient.Get("http://example.com/index.html")
	suite.Nil(err, "basic HTTP requests should succeed")
	resp.Body.Close()

	resp, err = suite.httpClient.Get("https://example.org/index.html")
	suite.Nil(err, "basic HTTPS requests should succeed")
	resp.Body.Close()
}

func (suite *StatsTestSuite) Test_TakeOutStatsForServer() {

	zeroPayload := &AccumulatedStats{hostnameToStats: make(map[string]*hostStats)}

	payload := TakeOutStatsForServer(suite.serverID)
	suite.Equal(payload, zeroPayload, "should get zero stats before any traffic")

	resp, err := suite.httpClient.Get("http://example.com/index.html")
	suite.Nil(err, "need successful http to proceed with tests")
	resp.Body.Close()

	payload = TakeOutStatsForServer(suite.serverID)
	suite.NotNil(payload, "should receive valid payload for valid server ID")

	payloadJSON, err := json.Marshal(payload)
	var parsedJSON interface{}
	err = json.Unmarshal(payloadJSON, &parsedJSON)
	suite.Nil(err, "payload JSON should parse successfully")

	// After we retrieve the stats for a server, they should be cleared out of the tracked stats
	payload = TakeOutStatsForServer(suite.serverID)
	suite.Equal(payload, zeroPayload, "after retrieving stats for a server, there should be zero stats (until more data goes through)")
}

func (suite *StatsTestSuite) Test_PutBackStatsForServer() {
	resp, err := suite.httpClient.Get("http://example.com/index.html")
	suite.Nil(err, "need successful http to proceed with tests")
	resp.Body.Close()

	payloadToPutBack := TakeOutStatsForServer(suite.serverID)
	suite.NotNil(payloadToPutBack, "should receive valid payload for valid server ID")

	zeroPayload := &AccumulatedStats{hostnameToStats: make(map[string]*hostStats)}

	payload := TakeOutStatsForServer(suite.serverID)
	suite.Equal(payload, zeroPayload, "should be zero stats after getting them")

	PutBackStatsForServer(suite.serverID, payloadToPutBack)
	// PutBack is asynchronous, so we'll need to wait a moment for it to do its thing
	<-time.After(100 * time.Millisecond)

	payload = TakeOutStatsForServer(suite.serverID)
	suite.NotEqual(payload, zeroPayload, "stats should be re-added after putting back")
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

	regexps, notices := MakeRegexps(pageViewRegexes, httpsRequestRegexes)
	suite.NotNil(regexps, "should return a valid object")
	suite.Len(*regexps, 2, "should only have processed httpsRequestRegexes")
	suite.Len(notices, 0, "should return no notices")

	//
	// Test some bad regexps
	//

	httpsRequestRegexes[0]["regex"] = ""
	httpsRequestRegexes[0]["replace"] = "$1"
	regexps, notices = MakeRegexps(pageViewRegexes, httpsRequestRegexes)
	suite.NotNil(regexps, "should return a valid object")
	suite.Len(*regexps, 1, "should have discarded one regexp")
	suite.Len(notices, 1, "should have returned one notice")

	httpsRequestRegexes[0]["regex"] = `^[a-z0-9\.]*\.(example\.com)$`
	httpsRequestRegexes[0]["replace"] = ""
	regexps, notices = MakeRegexps(pageViewRegexes, httpsRequestRegexes)
	suite.NotNil(regexps, "should return a valid object")
	suite.Len(*regexps, 1, "should have discarded one regexp")
	suite.Len(notices, 1, "should have returned one notice")

	httpsRequestRegexes[0]["regex"] = `^[a-z0-9\.]*\.(example\.com$` // missing closing paren
	httpsRequestRegexes[0]["replace"] = "$1"
	regexps, notices = MakeRegexps(pageViewRegexes, httpsRequestRegexes)
	suite.NotNil(regexps, "should return a valid object")
	suite.Len(*regexps, 1, "should have discarded one regexp")
	suite.Len(notices, 1, "should have returned one notice")
}

func (suite *StatsTestSuite) Test_Regex() {
	// We'll make a new client with actual regexps.
	pageViewRegexes := make([]map[string]string, 0)
	httpsRequestRegexes := []map[string]string{make(map[string]string), make(map[string]string)}
	httpsRequestRegexes[0]["regex"] = `^[a-z0-9\.]*\.(example\.com)$`
	httpsRequestRegexes[0]["replace"] = "$1"
	httpsRequestRegexes[1]["regex"] = `^.*example\.org$`
	httpsRequestRegexes[1]["replace"] = "replacement"
	regexps, _ := MakeRegexps(pageViewRegexes, httpsRequestRegexes)

	suite.httpClient = &http.Client{
		Transport: &http.Transport{
			Dial: makeStatsDialer(suite.serverID, regexps),
		},
	}

	// Using both HTTP and HTTPS will help us to exercise both methods of hostname parsing
	for _, scheme := range []string{"http", "https"} {
		// No subdomain, so won't match regex
		url := fmt.Sprintf("%s://example.com/index.html", scheme)
		resp, err := suite.httpClient.Get(url)
		suite.Nil(err)
		resp.Body.Close()

		// Will match the first regex
		url = fmt.Sprintf("%s://www.example.com/index.html", scheme)
		resp, err = suite.httpClient.Get(url)
		suite.Nil(err)
		resp.Body.Close()

		// Will match the second regex
		url = fmt.Sprintf("%s://example.org/index.html", scheme)
		resp, err = suite.httpClient.Get(url)
		suite.Nil(err)
		resp.Body.Close()

		payload := TakeOutStatsForServer(suite.serverID)
		suite.NotNil(payload, "should get stats because we made HTTP reqs; %s", scheme)

		expectedHostnames := mapset.NewSet()
		expectedHostnames.Add("(OTHER)")
		expectedHostnames.Add("example.com")
		expectedHostnames.Add("replacement")

		hostnames := make([]interface{}, 0)
		for hostname := range payload.hostnameToStats {
			hostnames = append(hostnames, hostname)
		}

		actualHostnames := mapset.NewSetFromSlice(hostnames)

		suite.Equal(expectedHostnames, actualHostnames, "post-regex hostnames should be processed as expecteds; %s", scheme)
	}
}

func (suite *StatsTestSuite) Test_getTLSHostname() {
	// TODO: Create a more robust/antagonistic set of negative tests.
	// We can write raw TCP to simulate any arbitrary degree of "almost looks
	// like a TLS handshake".
	// These tests are basically just checking for crashes.
	//
	// An easier way to construct valid client-hello messages (but not malicious ones)
	// would be to use the clientHelloMsg struct and marshal function from:
	// https://github.com/golang/go/blob/master/src/crypto/tls/handshake_messages.go

	// TODO: Talk to a local TCP server instead of spamming example.com

	dialer := makeStatsDialer(suite.serverID, nil)

	// Data too short
	conn, err := dialer("tcp", "example.com:80")
	suite.Nil(err)
	b := []byte(`my bytes`)
	n, err := conn.Write(b)
	suite.Nil(err)
	suite.Equal(len(b), n)
	err = conn.Close()
	suite.Nil(err)

	// Data long enough, but wrong first byte
	conn, err = dialer("tcp", "example.com:80")
	suite.Nil(err)
	b = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	n, err = conn.Write(b)
	suite.Nil(err)
	suite.Equal(len(b), n)
	err = conn.Close()
	suite.Nil(err)

	// Data long enough, correct first byte
	conn, err = dialer("tcp", "example.com:80")
	suite.Nil(err)
	b = []byte{22, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	n, err = conn.Write(b)
	suite.Nil(err)
	suite.Equal(len(b), n)
	err = conn.Close()
	suite.Nil(err)

	// Correct until after SSL version
	conn, err = dialer("tcp", "example.com:80")
	suite.Nil(err)
	b = []byte{22, 3, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	n, err = conn.Write(b)
	suite.Nil(err)
	suite.Equal(len(b), n)
	err = conn.Close()
	suite.Nil(err)

	plaintextLen := byte(70)

	// Correct until after plaintext length
	conn, err = dialer("tcp", "example.com:80")
	suite.Nil(err)
	b = []byte{22, 3, 1, 0, plaintextLen, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	n, err = conn.Write(b)
	suite.Nil(err)
	suite.Equal(len(b), n)
	err = conn.Close()
	suite.Nil(err)

	// Correct until after handshake type
	conn, err = dialer("tcp", "example.com:80")
	suite.Nil(err)
	b = []byte{22, 3, 1, 0, plaintextLen, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	n, err = conn.Write(b)
	suite.Nil(err)
	suite.Equal(len(b), n)
	err = conn.Close()
	suite.Nil(err)

	// Correct until after handshake length
	conn, err = dialer("tcp", "example.com:80")
	suite.Nil(err)
	b = []byte{22, 3, 1, 0, plaintextLen, 1, 0, 0, plaintextLen - 4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	n, err = conn.Write(b)
	suite.Nil(err)
	suite.Equal(len(b), n)
	err = conn.Close()
	suite.Nil(err)

	// Correct until after protocol version
	conn, err = dialer("tcp", "example.com:80")
	suite.Nil(err)
	b = []byte{22, 3, 1, 0, plaintextLen, 1, 0, 0, plaintextLen - 4, 3, 3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	n, err = conn.Write(b)
	suite.Nil(err)
	suite.Equal(len(b), n)
	err = conn.Close()
	suite.Nil(err)
}
