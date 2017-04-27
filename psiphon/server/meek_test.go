/*
 * Copyright (c) 2017, Psiphon Inc.
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
	"bytes"
	crypto_rand "crypto/rand"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Psiphon-Inc/crypto/nacl/box"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

var KB = 1024
var MB = KB * KB

func TestCachedResponse(t *testing.T) {

	rand.Seed(time.Now().Unix())

	testCases := []struct {
		concurrentResponses int
		responseSize        int
		bufferSize          int
		extendedBufferSize  int
		extendedBufferCount int
		minBytesPerWrite    int
		maxBytesPerWrite    int
		copyPosition        int
		expectedSuccess     bool
	}{
		{1, 16, 16, 0, 0, 1, 1, 0, true},

		{1, 31, 16, 0, 0, 1, 1, 15, true},

		{1, 16, 2, 2, 7, 1, 1, 0, true},

		{1, 31, 15, 3, 5, 1, 1, 1, true},

		{1, 10 * MB, 64 * KB, 64 * KB, 158, 1, 32 * KB, 0, false},

		{1, 10 * MB, 64 * KB, 64 * KB, 159, 1, 32 * KB, 0, true},

		{1, 10 * MB, 64 * KB, 64 * KB, 160, 1, 32 * KB, 0, true},

		{1, 128 * KB, 64 * KB, 0, 0, 1, 1 * KB, 64 * KB, true},

		{1, 128 * KB, 64 * KB, 0, 0, 1, 1 * KB, 63 * KB, false},

		{1, 200 * KB, 64 * KB, 0, 0, 1, 1 * KB, 136 * KB, true},

		{10, 10 * MB, 64 * KB, 64 * KB, 1589, 1, 32 * KB, 0, false},

		{10, 10 * MB, 64 * KB, 64 * KB, 1590, 1, 32 * KB, 0, true},
	}

	for _, testCase := range testCases {
		description := fmt.Sprintf("test case: %+v", testCase)
		t.Run(description, func(t *testing.T) {

			pool := NewCachedResponseBufferPool(testCase.extendedBufferSize, testCase.extendedBufferCount)

			responses := make([]*CachedResponse, testCase.concurrentResponses)
			for i := 0; i < testCase.concurrentResponses; i++ {
				responses[i] = NewCachedResponse(testCase.bufferSize, pool)
			}

			// Repeats exercise CachedResponse.Reset() and CachedResponseBufferPool replacement
			for repeat := 0; repeat < 2; repeat++ {

				t.Logf("repeat %d", repeat)

				responseData := make([]byte, testCase.responseSize)
				_, _ = rand.Read(responseData)

				waitGroup := new(sync.WaitGroup)

				// Goroutines exercise concurrent access to CachedResponseBufferPool
				for _, response := range responses {
					waitGroup.Add(1)
					go func(response *CachedResponse) {
						defer waitGroup.Done()

						remainingSize := testCase.responseSize
						for remainingSize > 0 {

							writeSize := testCase.minBytesPerWrite
							writeSize += rand.Intn(testCase.maxBytesPerWrite - testCase.minBytesPerWrite + 1)
							if writeSize > remainingSize {
								writeSize = remainingSize
							}

							offset := len(responseData) - remainingSize

							response.Write(responseData[offset : offset+writeSize])

							remainingSize -= writeSize
						}
					}(response)
				}

				waitGroup.Wait()

				atLeastOneFailure := false

				for i, response := range responses {

					cachedResponseData := new(bytes.Buffer)

					err := response.CopyFromPosition(testCase.copyPosition, cachedResponseData)

					if testCase.expectedSuccess {

						if err != nil {
							t.Fatalf("CopyFromPosition unexpectedly failed for response %d: %s", i, err)
						}

						if bytes.Compare(responseData[testCase.copyPosition:], cachedResponseData.Bytes()) != 0 {

							t.Fatalf("cached response data mismatch for response %d", i)
						}
					} else {
						atLeastOneFailure = true
					}
				}

				if !testCase.expectedSuccess && !atLeastOneFailure {
					t.Fatalf("CopyFromPosition unexpectedly succeeded for all responses")
				}

				for _, response := range responses {
					response.Reset()
				}
			}
		})
	}
}

func TestMeekResiliency(t *testing.T) {

	upstreamData := make([]byte, 10*MB)
	_, _ = rand.Read(upstreamData)

	downstreamData := make([]byte, 10*MB)
	_, _ = rand.Read(downstreamData)

	minWrite, maxWrite := 1, 128*KB
	minRead, maxRead := 1, 128*KB
	minWait, maxWait := 1*time.Millisecond, 500*time.Millisecond

	sendFunc := func(name string, conn net.Conn, data []byte) {
		for sent := 0; sent < len(data); {
			writeLen := minWrite + rand.Intn(maxWrite-minWrite+1)
			writeLen = min(writeLen, len(data)-sent)
			_, err := conn.Write(data[sent : sent+writeLen])
			if err != nil {
				t.Fatalf("conn.Write failed: %s", err)
			}
			sent += writeLen
			fmt.Printf("%s sent %d/%d...\n", name, sent, len(data))
			wait := minWait + time.Duration(rand.Int63n(int64(maxWait-minWait)+1))
			time.Sleep(wait)
		}
		fmt.Printf("%s send complete\n", name)
	}

	recvFunc := func(name string, conn net.Conn, expectedData []byte) {
		data := make([]byte, len(expectedData))
		for received := 0; received < len(data); {
			readLen := minRead + rand.Intn(maxRead-minRead+1)
			readLen = min(readLen, len(data)-received)
			n, err := conn.Read(data[received : received+readLen])
			if err != nil {
				t.Fatalf("conn.Read failed: %s", err)
			}
			received += n
			fmt.Printf("%s received %d/%d...\n", name, received, len(expectedData))
			wait := minWait + time.Duration(rand.Int63n(int64(maxWait-minWait)+1))
			time.Sleep(wait)
		}
		if bytes.Compare(data, expectedData) != 0 {
			t.Fatalf("unexpected data")
		}
		fmt.Printf("%s receive complete\n", name)
	}

	// Run meek server

	rawMeekCookieEncryptionPublicKey, rawMeekCookieEncryptionPrivateKey, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		t.Fatalf("box.GenerateKey failed: %s", err)
	}
	meekCookieEncryptionPublicKey := base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPublicKey[:])
	meekCookieEncryptionPrivateKey := base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPrivateKey[:])
	meekObfuscatedKey, err := common.MakeRandomStringHex(SSH_OBFUSCATED_KEY_BYTE_LENGTH)
	if err != nil {
		t.Fatalf("common.MakeRandomStringHex failed: %s", err)
	}

	mockSupport := &SupportServices{
		Config: &Config{
			MeekObfuscatedKey:              meekObfuscatedKey,
			MeekCookieEncryptionPrivateKey: meekCookieEncryptionPrivateKey,
		},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %s", err)
	}
	defer listener.Close()

	serverAddress := listener.Addr().String()

	relayWaitGroup := new(sync.WaitGroup)

	clientHandler := func(conn net.Conn) {
		name := "server"
		relayWaitGroup.Add(1)
		go func() {
			defer relayWaitGroup.Done()
			sendFunc(name, conn, downstreamData)
		}()
		relayWaitGroup.Add(1)
		go func() {
			defer relayWaitGroup.Done()
			recvFunc(name, conn, upstreamData)
		}()
	}

	stopBroadcast := make(chan struct{})

	useTLS := false
	useObfuscatedSessionTickets := false

	server, err := NewMeekServer(
		mockSupport,
		listener,
		useTLS,
		useObfuscatedSessionTickets,
		clientHandler,
		stopBroadcast)
	if err != nil {
		t.Fatalf("NewMeekServer failed: %s", err)
	}

	serverWaitGroup := new(sync.WaitGroup)

	serverWaitGroup.Add(1)
	go func() {
		defer serverWaitGroup.Done()
		err := server.Run()
		if err != nil {
			t.Fatalf("MeekServer.Run failed: %s", err)
		}
	}()

	// Run meek client

	dialConfig := &psiphon.DialConfig{
		PendingConns:            new(common.Conns),
		UseIndistinguishableTLS: true,
		DeviceBinder:            new(fileDescriptorInterruptor),
	}

	meekConfig := &psiphon.MeekConfig{
		DialAddress:                   serverAddress,
		UseHTTPS:                      useTLS,
		UseObfuscatedSessionTickets:   useObfuscatedSessionTickets,
		HostHeader:                    "example.com",
		MeekCookieEncryptionPublicKey: meekCookieEncryptionPublicKey,
		MeekObfuscatedKey:             meekObfuscatedKey,
	}

	clientConn, err := psiphon.DialMeek(meekConfig, dialConfig)
	if err != nil {
		t.Fatalf("psiphon.DialMeek failed: %s", err)
	}

	// Relay data through meek while interrupting underlying TCP connections

	name := "client"

	relayWaitGroup.Add(1)
	go func() {
		defer relayWaitGroup.Done()
		sendFunc(name, clientConn, upstreamData)
	}()

	relayWaitGroup.Add(1)
	go func() {
		defer relayWaitGroup.Done()
		recvFunc(name, clientConn, downstreamData)
	}()

	relayWaitGroup.Wait()

	// Graceful shutdown

	clientConn.Close()

	listener.Close()
	close(stopBroadcast)

	// This wait will hang if shutdown is broken, and the test will ultimately panic
	serverWaitGroup.Wait()
}

type fileDescriptorInterruptor struct {
}

func (interruptor *fileDescriptorInterruptor) BindToDevice(fileDescriptor int) error {
	fdDup, err := syscall.Dup(fileDescriptor)
	if err != nil {
		return err
	}
	time.AfterFunc(time.Second*2, func() {
		syscall.Shutdown(fdDup, syscall.SHUT_RDWR)
		syscall.Close(fdDup)
		fmt.Printf("interrupted TCP connection\n")
	})
	return nil
}
