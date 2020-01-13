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

package obfuscator

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func TestObfuscator(t *testing.T) {

	keyword := prng.HexString(32)

	maxPadding := 256

	paddingPRNGSeed, err := prng.NewSeed()
	if err != nil {
		t.Fatalf("prng.NewSeed failed: %s", err)
	}

	var irregularLogFields common.LogFields

	config := &ObfuscatorConfig{
		Keyword:         keyword,
		MaxPadding:      &maxPadding,
		PaddingPRNGSeed: paddingPRNGSeed,
		SeedHistory:     NewSeedHistory(&SeedHistoryConfig{ClientIPTTL: 500 * time.Millisecond}),
		IrregularLogger: func(_ string, logFields common.LogFields) {
			irregularLogFields = logFields
			t.Logf("IrregularLogger: %+v", logFields)
		},
	}

	client, err := NewClientObfuscator(config)
	if err != nil {
		t.Fatalf("NewClientObfuscator failed: %s", err)
	}

	seedMessage := client.SendSeedMessage()

	server, err := NewServerObfuscator(config, "", bytes.NewReader(seedMessage))
	if err != nil {
		t.Fatalf("NewServerObfuscator failed: %s", err)
	}

	clientMessage := []byte("client hello")

	b := append([]byte(nil), clientMessage...)
	client.ObfuscateClientToServer(b)
	server.ObfuscateClientToServer(b)

	if !bytes.Equal(clientMessage, b) {
		t.Fatalf("unexpected client message")
	}

	serverMessage := []byte("server hello")

	b = append([]byte(nil), serverMessage...)
	client.ObfuscateServerToClient(b)
	server.ObfuscateServerToClient(b)

	if !bytes.Equal(serverMessage, b) {
		t.Fatalf("unexpected client message")
	}

	// Test: duplicate obfuscation seed cases

	client, err = NewClientObfuscator(config)
	if err != nil {
		t.Fatalf("NewClientObfuscator failed: %s", err)
	}

	seedMessage = client.SendSeedMessage()

	clientIP := "192.168.0.1"

	_, err = NewServerObfuscator(config, clientIP, bytes.NewReader(seedMessage))
	if err != nil {
		t.Fatalf("NewServerObfuscator failed: %s", err)
	}

	irregularLogFields = nil

	_, err = NewServerObfuscator(config, clientIP, bytes.NewReader(seedMessage))
	if err != nil {
		t.Fatalf("NewServerObfuscator failed: %s", err)
	}

	duplicateClientID := irregularLogFields["duplicate_client_ip"]
	if duplicateClientID != "equal" {
		t.Fatalf("Unexpected duplicate_client_ip: %s", duplicateClientID)
	}

	irregularLogFields = nil

	_, err = NewServerObfuscator(config, "192.168.0.2", bytes.NewReader(seedMessage))
	if err == nil {
		t.Fatalf("NewServerObfuscator unexpectedly succeeded")
	}

	duplicateClientID = irregularLogFields["duplicate_client_ip"]
	if duplicateClientID != "unequal" {
		t.Fatalf("Unexpected duplicate_client_ip: %s", duplicateClientID)
	}

	time.Sleep(600 * time.Millisecond)

	irregularLogFields = nil

	_, err = NewServerObfuscator(config, clientIP, bytes.NewReader(seedMessage))
	if err == nil {
		t.Fatalf("NewServerObfuscator unexpectedly succeeded")
	}

	duplicateClientID = irregularLogFields["duplicate_client_ip"]
	if duplicateClientID != "unknown" {
		t.Fatalf("Unexpected duplicate_client_ip: %s", duplicateClientID)
	}
}

func TestObfuscatedSSHConn(t *testing.T) {

	keyword := prng.HexString(32)

	serverAddress := "127.0.0.1:2222"

	listener, err := net.Listen("tcp", serverAddress)
	if err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %s", err)
	}

	hostKey, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey failed: %s", err)
	}

	sshCertChecker := &ssh.CertChecker{
		HostKeyFallback: func(addr string, remote net.Addr, publicKey ssh.PublicKey) error {
			if !bytes.Equal(hostKey.PublicKey().Marshal(), publicKey.Marshal()) {
				return errors.New("unexpected host public key")
			}
			return nil
		},
	}

	result := make(chan error, 1)

	go func() {

		conn, err := listener.Accept()

		if err == nil {
			conn, err = NewServerObfuscatedSSHConn(
				conn,
				keyword,
				NewSeedHistory(nil),
				func(_ string, logFields common.LogFields) {
					t.Logf("IrregularLogger: %+v", logFields)
				})
		}

		if err == nil {
			config := &ssh.ServerConfig{
				NoClientAuth: true,
			}
			config.AddHostKey(hostKey)

			_, _, _, err = ssh.NewServerConn(conn, config)
		}

		if err != nil {
			select {
			case result <- err:
			default:
			}
		}
	}()

	go func() {

		conn, err := net.DialTimeout("tcp", serverAddress, 5*time.Second)

		var paddingPRNGSeed *prng.Seed
		if err == nil {
			paddingPRNGSeed, err = prng.NewSeed()
		}

		if err == nil {
			conn, err = NewClientObfuscatedSSHConn(
				conn,
				keyword,
				paddingPRNGSeed,
				nil, nil)
		}

		var KEXPRNGSeed *prng.Seed
		if err == nil {
			KEXPRNGSeed, err = prng.NewSeed()
		}

		if err == nil {
			config := &ssh.ClientConfig{
				HostKeyCallback: sshCertChecker.CheckHostKey,
			}
			config.KEXPRNGSeed = KEXPRNGSeed
			_, _, _, err = ssh.NewClientConn(conn, "", config)
		}

		// Sends nil on success
		select {
		case result <- err:
		default:
		}
	}()

	err = <-result
	if err != nil {
		t.Fatalf("obfuscated SSH handshake failed: %s", err)
	}
}
