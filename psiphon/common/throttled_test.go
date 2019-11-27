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
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"testing"
	"time"
)

const (
	serverAddress = "127.0.0.1:8081"
	testDataSize  = 10 * 1024 * 1024 // 10 MB
)

func TestThrottledConnRates(t *testing.T) {

	runRateLimitsTest(t, RateLimits{
		ReadUnthrottledBytes:  0,
		ReadBytesPerSecond:    0,
		WriteUnthrottledBytes: 0,
		WriteBytesPerSecond:   0,
	})

	runRateLimitsTest(t, RateLimits{
		ReadUnthrottledBytes:  0,
		ReadBytesPerSecond:    5 * 1024 * 1024,
		WriteUnthrottledBytes: 0,
		WriteBytesPerSecond:   5 * 1024 * 1024,
	})

	runRateLimitsTest(t, RateLimits{
		ReadUnthrottledBytes:  0,
		ReadBytesPerSecond:    5 * 1024 * 1024,
		WriteUnthrottledBytes: 0,
		WriteBytesPerSecond:   1024 * 1024,
	})

	runRateLimitsTest(t, RateLimits{
		ReadUnthrottledBytes:  0,
		ReadBytesPerSecond:    2 * 1024 * 1024,
		WriteUnthrottledBytes: 0,
		WriteBytesPerSecond:   2 * 1024 * 1024,
	})

	runRateLimitsTest(t, RateLimits{
		ReadUnthrottledBytes:  0,
		ReadBytesPerSecond:    1024 * 1024,
		WriteUnthrottledBytes: 0,
		WriteBytesPerSecond:   1024 * 1024,
	})

	// This test takes > 1 min to run, so disabled for now
	/*
		runRateLimitsTest(t, RateLimits{
			ReadUnthrottledBytes: 0,
			ReadBytesPerSecond: 1024 * 1024 / 8,
			WriteUnthrottledBytes:   0,
			WriteBytesPerSecond:   1024 * 1024 / 8,
		})
	*/
}

func runRateLimitsTest(t *testing.T, rateLimits RateLimits) {

	// Run a local HTTP server which serves large chunks of data

	go func() {

		handler := func(w http.ResponseWriter, r *http.Request) {
			_, _ = ioutil.ReadAll(r.Body)
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

	// Upload and download a large chunk of data, and time it

	testData, _ := MakeSecureRandomBytes(testDataSize)
	requestBody := bytes.NewReader(testData)

	startTime := time.Now()

	response, err := client.Post("http://"+serverAddress, "application/octet-stream", requestBody)
	if err == nil && response.StatusCode != http.StatusOK {
		response.Body.Close()
		err = fmt.Errorf("unexpected response code: %d", response.StatusCode)
	}
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	defer response.Body.Close()

	// Test: elapsed upload time must reflect rate limit

	checkElapsedTime(t, testDataSize, rateLimits.WriteBytesPerSecond, time.Since(startTime))

	startTime = time.Now()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response failed: %s", err)
	}
	if len(body) != testDataSize {
		t.Fatalf("unexpected response size: %d", len(body))
	}

	// Test: elapsed download time must reflect rate limit

	checkElapsedTime(t, testDataSize, rateLimits.ReadBytesPerSecond, time.Since(startTime))
}

func checkElapsedTime(t *testing.T, dataSize int, rateLimit int64, duration time.Duration) {

	// With no rate limit, should finish under a couple seconds
	floorElapsedTime := 0 * time.Second
	ceilingElapsedTime := 2 * time.Second

	if rateLimit != 0 {
		// With rate limit, should finish within a couple seconds or so of data size / bytes-per-second;
		// won't be exact due to request overhead and approximations in "ratelimit" package
		expectedElapsedTime := float64(testDataSize) / float64(rateLimit)
		floorElapsedTime = time.Duration(int64(math.Floor(expectedElapsedTime))) * time.Second
		floorElapsedTime -= 1500 * time.Millisecond
		if floorElapsedTime < 0 {
			floorElapsedTime = 0
		}
		ceilingElapsedTime = time.Duration(int64(math.Ceil(expectedElapsedTime))) * time.Second
		ceilingElapsedTime += 1500 * time.Millisecond
	}

	t.Logf(
		"\ndata size: %d\nrate limit: %d\nelapsed time: %s\nexpected time: [%s,%s]\n\n",
		dataSize,
		rateLimit,
		duration,
		floorElapsedTime,
		ceilingElapsedTime)

	if duration < floorElapsedTime {
		t.Errorf("unexpected duration: %s < %s", duration, floorElapsedTime)
	}

	if duration > ceilingElapsedTime {
		t.Errorf("unexpected duration: %s > %s", duration, ceilingElapsedTime)
	}
}

func TestThrottledConnClose(t *testing.T) {

	rateLimits := RateLimits{
		ReadBytesPerSecond:  1,
		WriteBytesPerSecond: 1,
	}

	n := 4
	b := make([]byte, n+1)

	throttledConn := NewThrottledConn(&testConn{}, rateLimits)

	now := time.Now()
	_, err := throttledConn.Read(b)
	elapsed := time.Since(now)
	if err != nil || elapsed < time.Duration(n)*time.Second {
		t.Errorf("unexpected interrupted read: %s, %v", elapsed, err)
	}

	now = time.Now()
	go func() {
		time.Sleep(500 * time.Millisecond)
		throttledConn.Close()
	}()
	_, err = throttledConn.Read(b)
	elapsed = time.Since(now)
	if elapsed > 1*time.Second {
		t.Errorf("unexpected uninterrupted read: %s, %v", elapsed, err)
	}

	throttledConn = NewThrottledConn(&testConn{}, rateLimits)

	now = time.Now()
	_, err = throttledConn.Write(b)
	elapsed = time.Since(now)
	if err != nil || elapsed < time.Duration(n)*time.Second {
		t.Errorf("unexpected interrupted write: %s, %v", elapsed, err)
	}

	now = time.Now()
	go func() {
		time.Sleep(500 * time.Millisecond)
		throttledConn.Close()
	}()
	_, err = throttledConn.Write(b)
	elapsed = time.Since(now)
	if elapsed > 1*time.Second {
		t.Errorf("unexpected uninterrupted write: %s, %v", elapsed, err)
	}
}

type testConn struct {
}

func (conn *testConn) Read(b []byte) (n int, err error) {
	return len(b), nil
}

func (conn *testConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (conn *testConn) Close() error {
	return nil
}

func (conn *testConn) LocalAddr() net.Addr {
	return nil
}

func (conn *testConn) RemoteAddr() net.Addr {
	return nil
}

func (conn *testConn) SetDeadline(t time.Time) error {
	return nil
}

func (conn *testConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (conn *testConn) SetWriteDeadline(t time.Time) error {
	return nil
}
