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

package common

import (
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"testing"
	"time"
)

const (
	serverAddress = "127.0.0.1:8080"
	testDataSize  = 10 * 1024 * 1024 // 10 MB
)

func TestThrottledConn(t *testing.T) {

	run(t, RateLimits{
		DownstreamUnlimitedBytes: 0,
		DownstreamBytesPerSecond: 0,
		UpstreamUnlimitedBytes:   0,
		UpstreamBytesPerSecond:   0,
	})

	run(t, RateLimits{
		DownstreamUnlimitedBytes: 0,
		DownstreamBytesPerSecond: 5 * 1024 * 1024,
		UpstreamUnlimitedBytes:   0,
		UpstreamBytesPerSecond:   0,
	})

	run(t, RateLimits{
		DownstreamUnlimitedBytes: 0,
		DownstreamBytesPerSecond: 2 * 1024 * 1024,
		UpstreamUnlimitedBytes:   0,
		UpstreamBytesPerSecond:   0,
	})

	run(t, RateLimits{
		DownstreamUnlimitedBytes: 0,
		DownstreamBytesPerSecond: 1024 * 1024,
		UpstreamUnlimitedBytes:   0,
		UpstreamBytesPerSecond:   0,
	})
}

func run(t *testing.T, rateLimits RateLimits) {

	// Run a local HTTP server which serves large chunks of data

	go func() {

		handler := func(w http.ResponseWriter, r *http.Request) {
			testData, _ := MakeSecureRandomBytes(testDataSize)
			w.Write(testData)
		}

		server := &http.Server{
			Addr:    serverAddress,
			Handler: http.HandlerFunc(handler),
		}

		server.ListenAndServe()
	}()

	// TODO: properly synchronize with server startup
	time.Sleep(1 * time.Second)

	// Set up a HTTP client with a throttled connection

	throttledDial := func(network, addr string) (net.Conn, error) {
		conn, err := net.Dial(network, addr)
		if err != nil {
			return conn, err
		}
		return NewThrottledConn(conn, rateLimits), nil
	}

	client := &http.Client{
		Transport: &http.Transport{
			Dial: throttledDial,
		},
	}

	// Download a large chunk of data, and time it

	startTime := time.Now()

	response, err := client.Get("http://" + serverAddress)
	if err == nil && response.StatusCode != http.StatusOK {
		response.Body.Close()
		err = fmt.Errorf("unexpected response code: %d", response.StatusCode)
	}
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response failed: %s", err)
	}
	if len(body) != testDataSize {
		t.Fatalf("unexpected response size: %d", len(body))
	}

	duration := time.Now().Sub(startTime)

	// Test: elapsed time must reflect rate limit

	// No rate limit should finish under a couple seconds
	floorElapsedTime := 0 * time.Second
	ceilingElapsedTime := 2 * time.Second

	if rateLimits.DownstreamBytesPerSecond != 0 {
		// With rate limit, should finish within a couple seconds or so of data size / bytes-per-second;
		// won't be eaxact due to request overhead and approximations in "ratelimit" package
		expectedElapsedTime := float64(testDataSize) / float64(rateLimits.DownstreamBytesPerSecond)
		floorElapsedTime = time.Duration(int64(math.Floor(expectedElapsedTime))) * time.Second
		floorElapsedTime -= 1500 * time.Millisecond
		if floorElapsedTime < 0 {
			floorElapsedTime = 0
		}
		ceilingElapsedTime = time.Duration(int64(math.Ceil(expectedElapsedTime))) * time.Second
		ceilingElapsedTime += 1500 * time.Millisecond
	}

	t.Logf(
		"data size: %d; downstream rate limit: %d; elapsed time: %s; expected time: [%s,%s]",
		testDataSize,
		rateLimits.DownstreamBytesPerSecond,
		duration,
		floorElapsedTime,
		ceilingElapsedTime)

	if duration < floorElapsedTime {
		t.Fatalf("unexpected duration: %s < %s", duration, floorElapsedTime)
	}

	if duration > ceilingElapsedTime {
		t.Fatalf("unexpected duration: %s > %s", duration, ceilingElapsedTime)
	}
}
