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

package tls

import (
	"crypto/rand"
	"math/big"
)

// NewObfuscatedClientSessionCache produces obfuscated session tickets.
//
// [Psiphon]
// Obfuscated Session Tickets
//
// Obfuscated session tickets is a network traffic obfuscation protocol that appears
// to be valid TLS using session tickets. The client actually generates the session
// ticket and encrypts it with a shared secret, enabling a TLS session that entirely
// skips the most fingerprintable aspects of TLS.
// The scheme is described here:
// https://lists.torproject.org/pipermail/tor-dev/2016-September/011354.html
//
// Circumvention notes:
//  - TLS session ticket implementations are widespread:
//    https://istlsfastyet.com/#cdn-paas.
//  - An adversary cannot easily block session ticket capability, as this requires
//    a downgrade attack against TLS.
//  - Anti-probing defence is provided, as the adversary must use the correct obfuscation
//    shared secret to form valid obfuscation session ticket; otherwise server offers
//    standard session tickets.
//  - Limitation: TLS protocol and session ticket size correspond to golang implementation
//    and not more common OpenSSL.
//  - Limitation: an adversary with the obfuscation shared secret can decrypt the session
//    ticket and observe the plaintext traffic. It's assumed that the adversary will not
//    learn the obfuscated shared secret without also learning the address of the TLS
//    server and blocking it anyway; it's also assumed that the TLS payload is not
//    plaintext but is protected with some other security layer (e.g., SSH).
//
// Implementation notes:
//   - Client should set its ClientSessionCache to a NewObfuscatedTLSClientSessionCache.
//     This cache ignores the session key and always produces obfuscated session tickets.
//   - The TLS ClientHello includes an SNI field, even when using session tickets, so
//     the client should populate the ServerName.
//   - Server should set its SetSessionTicketKeys with first a standard key, followed by
//     the obfuscation shared secret.
//   - Since the client creates the session ticket, it selects parameters that were not
//     negotiated with the server, such as the cipher suite. It's implicitly assumed that
//     the server can support the selected parameters.
//
func NewObfuscatedClientSessionCache(sharedSecret [32]byte) ClientSessionCache {
	return &obfuscatedClientSessionCache{
		sharedSecret: sharedSecret,
		realTickets:  NewLRUClientSessionCache(-1),
	}
}

type obfuscatedClientSessionCache struct {
	sharedSecret [32]byte
	realTickets  ClientSessionCache
}

func (cache *obfuscatedClientSessionCache) Put(key string, state *ClientSessionState) {
	// When new, real session tickets are issued, use them.
	cache.realTickets.Put(key, state)
}

func (cache *obfuscatedClientSessionCache) Get(key string) (*ClientSessionState, bool) {
	clientSessionState, ok := cache.realTickets.Get(key)
	if ok {
		return clientSessionState, true
	}
	// Bootstrap with an obfuscated session ticket.
	clientSessionState, err := NewObfuscatedClientSessionState(cache.sharedSecret)
	if err != nil {
		// TODO: log error
		// This will fall back to regular TLS
		return nil, false
	}
	return clientSessionState, true
}

func NewObfuscatedClientSessionState(sharedSecret [32]byte) (*ClientSessionState, error) {

	// Pad golang TLS session ticket to a more typical size.
	paddingSize := 72
	randomInt, err := rand.Int(rand.Reader, big.NewInt(18))
	if err != nil {
		return nil, err
	}
	paddingSize += int(randomInt.Int64()) * 2

	// Create a session ticket that wasn't actually issued by the server.
	vers := uint16(VersionTLS12)
	cipherSuite := TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	masterSecret := make([]byte, masterSecretLength)
	_, err = rand.Read(masterSecret)
	if err != nil {
		return nil, err
	}
	serverState := &sessionState{
		vers:         vers,
		cipherSuite:  cipherSuite,
		masterSecret: masterSecret,
		certificates: nil,
		paddingSize:  paddingSize,
	}
	c := &Conn{
		config: &Config{
			sessionTicketKeys: []ticketKey{ticketKeyFromBytes(sharedSecret)},
		},
	}
	sessionTicket, err := c.encryptTicket(serverState)
	if err != nil {
		return nil, err
	}

	// Pretend we got that session ticket from the server.
	clientState := &ClientSessionState{
		sessionTicket: sessionTicket,
		vers:          vers,
		cipherSuite:   cipherSuite,
		masterSecret:  masterSecret,
	}

	return clientState, nil
}
