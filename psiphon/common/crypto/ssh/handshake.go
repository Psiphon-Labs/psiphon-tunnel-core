// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	// [Psiphon]
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

// debugHandshake, if set, prints messages sent and received.  Key
// exchange messages are printed as if DH were used, so the debug
// messages are wrong when using ECDH.
const debugHandshake = false

// chanSize sets the amount of buffering SSH connections. This is
// primarily for testing: setting chanSize=0 uncovers deadlocks more
// quickly.
const chanSize = 16

// keyingTransport is a packet based transport that supports key
// changes. It need not be thread-safe. It should pass through
// msgNewKeys in both directions.
type keyingTransport interface {
	packetConn

	// prepareKeyChange sets up a key change. The key change for a
	// direction will be effected if a msgNewKeys message is sent
	// or received.
	prepareKeyChange(*algorithms, *kexResult) error
}

// handshakeTransport implements rekeying on top of a keyingTransport
// and offers a thread-safe writePacket() interface.
type handshakeTransport struct {
	conn   keyingTransport
	config *Config

	serverVersion []byte
	clientVersion []byte

	// hostKeys is non-empty if we are the server. In that case,
	// it contains all host keys that can be used to sign the
	// connection.
	hostKeys []Signer

	// hostKeyAlgorithms is non-empty if we are the client. In that case,
	// we accept these key types from the server as host key.
	hostKeyAlgorithms []string

	// On read error, incoming is closed, and readError is set.
	incoming  chan []byte
	readError error

	mu             sync.Mutex
	writeError     error
	sentInitPacket []byte
	sentInitMsg    *kexInitMsg
	pendingPackets [][]byte // Used when a key exchange is in progress.

	// If the read loop wants to schedule a kex, it pings this
	// channel, and the write loop will send out a kex
	// message.
	requestKex chan struct{}

	// If the other side requests or confirms a kex, its kexInit
	// packet is sent here for the write loop to find it.
	startKex chan *pendingKex

	// data for host key checking
	hostKeyCallback HostKeyCallback
	dialAddress     string
	remoteAddr      net.Addr

	// bannerCallback is non-empty if we are the client and it has been set in
	// ClientConfig. In that case it is called during the user authentication
	// dance to handle a custom server's message.
	bannerCallback BannerCallback

	// Algorithms agreed in the last key exchange.
	algorithms *algorithms

	readPacketsLeft uint32
	readBytesLeft   int64

	writePacketsLeft uint32
	writeBytesLeft   int64

	// The session ID or nil if first kex did not complete yet.
	sessionID []byte
}

type pendingKex struct {
	otherInit []byte
	done      chan error
}

func newHandshakeTransport(conn keyingTransport, config *Config, clientVersion, serverVersion []byte) *handshakeTransport {
	t := &handshakeTransport{
		conn:          conn,
		serverVersion: serverVersion,
		clientVersion: clientVersion,
		incoming:      make(chan []byte, chanSize),
		requestKex:    make(chan struct{}, 1),
		startKex:      make(chan *pendingKex, 1),

		config: config,
	}
	t.resetReadThresholds()
	t.resetWriteThresholds()

	// We always start with a mandatory key exchange.
	t.requestKex <- struct{}{}
	return t
}

func newClientTransport(conn keyingTransport, clientVersion, serverVersion []byte, config *ClientConfig, dialAddr string, addr net.Addr) *handshakeTransport {
	t := newHandshakeTransport(conn, &config.Config, clientVersion, serverVersion)
	t.dialAddress = dialAddr
	t.remoteAddr = addr
	t.hostKeyCallback = config.HostKeyCallback
	t.bannerCallback = config.BannerCallback
	if config.HostKeyAlgorithms != nil {
		t.hostKeyAlgorithms = config.HostKeyAlgorithms
	} else {
		t.hostKeyAlgorithms = supportedHostKeyAlgos
	}
	go t.readLoop()
	go t.kexLoop()
	return t
}

func newServerTransport(conn keyingTransport, clientVersion, serverVersion []byte, config *ServerConfig) *handshakeTransport {
	t := newHandshakeTransport(conn, &config.Config, clientVersion, serverVersion)
	t.hostKeys = config.hostKeys
	go t.readLoop()
	go t.kexLoop()
	return t
}

func (t *handshakeTransport) getSessionID() []byte {
	return t.sessionID
}

// waitSession waits for the session to be established. This should be
// the first thing to call after instantiating handshakeTransport.
func (t *handshakeTransport) waitSession() error {
	p, err := t.readPacket()
	if err != nil {
		return err
	}
	if p[0] != msgNewKeys {
		return fmt.Errorf("ssh: first packet should be msgNewKeys")
	}

	return nil
}

func (t *handshakeTransport) id() string {
	if len(t.hostKeys) > 0 {
		return "server"
	}
	return "client"
}

func (t *handshakeTransport) printPacket(p []byte, write bool) {
	action := "got"
	if write {
		action = "sent"
	}

	if p[0] == msgChannelData || p[0] == msgChannelExtendedData {
		log.Printf("%s %s data (packet %d bytes)", t.id(), action, len(p))
	} else {
		msg, err := decode(p)
		log.Printf("%s %s %T %v (%v)", t.id(), action, msg, msg, err)
	}
}

func (t *handshakeTransport) readPacket() ([]byte, error) {
	p, ok := <-t.incoming
	if !ok {
		return nil, t.readError
	}
	return p, nil
}

func (t *handshakeTransport) readLoop() {
	first := true
	for {
		p, err := t.readOnePacket(first)
		first = false
		if err != nil {
			t.readError = err
			close(t.incoming)
			break
		}
		if p[0] == msgIgnore || p[0] == msgDebug {
			continue
		}
		t.incoming <- p
	}

	// Stop writers too.
	t.recordWriteError(t.readError)

	// Unblock the writer should it wait for this.
	close(t.startKex)

	// Don't close t.requestKex; it's also written to from writePacket.
}

func (t *handshakeTransport) pushPacket(p []byte) error {
	if debugHandshake {
		t.printPacket(p, true)
	}
	return t.conn.writePacket(p)
}

func (t *handshakeTransport) getWriteError() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.writeError
}

func (t *handshakeTransport) recordWriteError(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.writeError == nil && err != nil {
		t.writeError = err
	}
}

func (t *handshakeTransport) requestKeyExchange() {
	select {
	case t.requestKex <- struct{}{}:
	default:
		// something already requested a kex, so do nothing.
	}
}

func (t *handshakeTransport) resetWriteThresholds() {
	t.writePacketsLeft = packetRekeyThreshold
	if t.config.RekeyThreshold > 0 {
		t.writeBytesLeft = int64(t.config.RekeyThreshold)
	} else if t.algorithms != nil {
		t.writeBytesLeft = t.algorithms.w.rekeyBytes()
	} else {
		t.writeBytesLeft = 1 << 30
	}
}

func (t *handshakeTransport) kexLoop() {

write:
	for t.getWriteError() == nil {
		var request *pendingKex
		var sent bool

		for request == nil || !sent {
			var ok bool
			select {
			case request, ok = <-t.startKex:
				if !ok {
					break write
				}
			case <-t.requestKex:
				break
			}

			if !sent {
				if err := t.sendKexInit(); err != nil {
					t.recordWriteError(err)
					break
				}
				sent = true
			}
		}

		if err := t.getWriteError(); err != nil {
			if request != nil {
				request.done <- err
			}
			break
		}

		// We're not servicing t.requestKex, but that is OK:
		// we never block on sending to t.requestKex.

		// We're not servicing t.startKex, but the remote end
		// has just sent us a kexInitMsg, so it can't send
		// another key change request, until we close the done
		// channel on the pendingKex request.

		err := t.enterKeyExchange(request.otherInit)

		t.mu.Lock()
		t.writeError = err
		t.sentInitPacket = nil
		t.sentInitMsg = nil

		t.resetWriteThresholds()

		// we have completed the key exchange. Since the
		// reader is still blocked, it is safe to clear out
		// the requestKex channel. This avoids the situation
		// where: 1) we consumed our own request for the
		// initial kex, and 2) the kex from the remote side
		// caused another send on the requestKex channel,
	clear:
		for {
			select {
			case <-t.requestKex:
				//
			default:
				break clear
			}
		}

		request.done <- t.writeError

		// kex finished. Push packets that we received while
		// the kex was in progress. Don't look at t.startKex
		// and don't increment writtenSinceKex: if we trigger
		// another kex while we are still busy with the last
		// one, things will become very confusing.
		for _, p := range t.pendingPackets {
			t.writeError = t.pushPacket(p)
			if t.writeError != nil {
				break
			}
		}
		t.pendingPackets = t.pendingPackets[:0]
		t.mu.Unlock()
	}

	// drain startKex channel. We don't service t.requestKex
	// because nobody does blocking sends there.
	go func() {
		for init := range t.startKex {
			init.done <- t.writeError
		}
	}()

	// Unblock reader.
	t.conn.Close()
}

// The protocol uses uint32 for packet counters, so we can't let them
// reach 1<<32.  We will actually read and write more packets than
// this, though: the other side may send more packets, and after we
// hit this limit on writing we will send a few more packets for the
// key exchange itself.
const packetRekeyThreshold = (1 << 31)

func (t *handshakeTransport) resetReadThresholds() {
	t.readPacketsLeft = packetRekeyThreshold
	if t.config.RekeyThreshold > 0 {
		t.readBytesLeft = int64(t.config.RekeyThreshold)
	} else if t.algorithms != nil {
		t.readBytesLeft = t.algorithms.r.rekeyBytes()
	} else {
		t.readBytesLeft = 1 << 30
	}
}

func (t *handshakeTransport) readOnePacket(first bool) ([]byte, error) {
	p, err := t.conn.readPacket()
	if err != nil {
		return nil, err
	}

	if t.readPacketsLeft > 0 {
		t.readPacketsLeft--
	} else {
		t.requestKeyExchange()
	}

	if t.readBytesLeft > 0 {
		t.readBytesLeft -= int64(len(p))
	} else {
		t.requestKeyExchange()
	}

	if debugHandshake {
		t.printPacket(p, false)
	}

	if first && p[0] != msgKexInit {
		return nil, fmt.Errorf("ssh: first packet should be msgKexInit")
	}

	if p[0] != msgKexInit {
		return p, nil
	}

	firstKex := t.sessionID == nil

	kex := pendingKex{
		done:      make(chan error, 1),
		otherInit: p,
	}
	t.startKex <- &kex
	err = <-kex.done

	if debugHandshake {
		log.Printf("%s exited key exchange (first %v), err %v", t.id(), firstKex, err)
	}

	if err != nil {
		return nil, err
	}

	t.resetReadThresholds()

	// By default, a key exchange is hidden from higher layers by
	// translating it into msgIgnore.
	successPacket := []byte{msgIgnore}
	if firstKex {
		// sendKexInit() for the first kex waits for
		// msgNewKeys so the authentication process is
		// guaranteed to happen over an encrypted transport.
		successPacket = []byte{msgNewKeys}
	}

	return successPacket, nil
}

// sendKexInit sends a key change message.
func (t *handshakeTransport) sendKexInit() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sentInitMsg != nil {
		// kexInits may be sent either in response to the other side,
		// or because our side wants to initiate a key change, so we
		// may have already sent a kexInit. In that case, don't send a
		// second kexInit.
		return nil
	}

	msg := &kexInitMsg{
		KexAlgos:                t.config.KeyExchanges,
		CiphersClientServer:     t.config.Ciphers,
		CiphersServerClient:     t.config.Ciphers,
		MACsClientServer:        t.config.MACs,
		MACsServerClient:        t.config.MACs,
		CompressionClientServer: supportedCompressions,
		CompressionServerClient: supportedCompressions,
	}
	io.ReadFull(rand.Reader, msg.Cookie[:])

	if len(t.hostKeys) > 0 {
		for _, k := range t.hostKeys {
			msg.ServerHostKeyAlgos = append(
				msg.ServerHostKeyAlgos, k.PublicKey().Type())
		}
	} else {
		msg.ServerHostKeyAlgos = t.hostKeyAlgorithms
	}

	// [Psiphon]
	//
	// When KEXPRNGSeed is specified, randomize the KEX. The offered
	// algorithms are shuffled and truncated. Longer lists are selected with
	// higher probability.
	//
	// When PeerKEXPRNGSeed is specified, the peer is expected to randomize
	// its KEX using the specified seed; deterministically adjust own
	// randomized KEX to ensure negotiation succeeds.
	//
	// When NoEncryptThenMACHash is specified, do not use Encrypt-then-MAC has
	// algorithms.

	equal := func(list1, list2 []string) bool {
		if len(list1) != len(list2) {
			return false
		}
		for i, entry := range list1 {
			if list2[i] != entry {
				return false
			}
		}
		return true
	}

	// Psiphon transforms assume that default algorithms are configured.
	if (t.config.NoEncryptThenMACHash || t.config.KEXPRNGSeed != nil) &&
		(!equal(t.config.KeyExchanges, supportedKexAlgos) ||
			!equal(t.config.Ciphers, preferredCiphers) ||
			!equal(t.config.MACs, supportedMACs)) {

		return errors.New("ssh: custom algorithm preferences not supported")
	}

	// This is the list of supported non-Encrypt-then-MAC algorithms from
	// https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/3ef11effe6acd9
	// 2c3aefd140ee09c42a1f15630b/psiphon/common/crypto/ssh/common.go#L60
	//
	// With Encrypt-then-MAC hash algorithms, packet length is transmitted in
	// plaintext, which aids in traffic analysis.
	//
	// When using obfuscated SSH, where only the initial, unencrypted
	// packets are obfuscated, NoEncryptThenMACHash should be set.
	noEncryptThenMACs := []string{"hmac-sha2-256", "hmac-sha1", "hmac-sha1-96"}

	if t.config.NoEncryptThenMACHash {
		msg.MACsClientServer = noEncryptThenMACs
		msg.MACsServerClient = noEncryptThenMACs
	}

	if t.config.KEXPRNGSeed != nil {

		PRNG := prng.NewPRNGWithSeed(t.config.KEXPRNGSeed)

		permute := func(PRNG *prng.PRNG, list []string) []string {
			newList := make([]string, len(list))
			perm := PRNG.Perm(len(list))
			for i, j := range perm {
				newList[j] = list[i]
			}
			return newList
		}

		truncate := func(PRNG *prng.PRNG, list []string) []string {
			cut := len(list)
			for ; cut > 1; cut-- {
				if !PRNG.FlipCoin() {
					break
				}
			}
			return list[:cut]
		}

		retain := func(PRNG *prng.PRNG, list []string, item string) []string {
			for _, entry := range list {
				if entry == item {
					return list
				}
			}
			replace := PRNG.Intn(len(list))
			list[replace] = item
			return list
		}

		msg.KexAlgos = truncate(PRNG, permute(PRNG, msg.KexAlgos))
		ciphers := truncate(PRNG, permute(PRNG, msg.CiphersClientServer))
		msg.CiphersClientServer = ciphers
		msg.CiphersServerClient = ciphers
		MACs := truncate(PRNG, permute(PRNG, msg.MACsClientServer))
		msg.MACsClientServer = MACs
		msg.MACsServerClient = MACs

		if len(t.hostKeys) > 0 {
			msg.ServerHostKeyAlgos = permute(PRNG, msg.ServerHostKeyAlgos)
		} else {
			// Must offer KeyAlgoRSA to Psiphon server.
			msg.ServerHostKeyAlgos = retain(
				PRNG,
				truncate(PRNG, permute(PRNG, msg.ServerHostKeyAlgos)),
				KeyAlgoRSA)
		}

		if t.config.PeerKEXPRNGSeed != nil {

			// Generate the peer KEX and make adjustments if negotiation would
			// fail. This assumes that PeerKEXPRNGSeed remains static (in
			// Psiphon, the peer is the server and PeerKEXPRNGSeed is derived
			// from the server entry); and that the PRNG is invoked in the
			// exact same order on the peer (i.e., the code block immediately
			// above is what the peer runs); and that the peer sets
			// NoEncryptThenMACHash in the same cases.

			PeerPRNG := prng.NewPRNGWithSeed(t.config.PeerKEXPRNGSeed)

			peerKexAlgos := truncate(PeerPRNG, permute(PeerPRNG, supportedKexAlgos))
			if _, err := findCommon("", msg.KexAlgos, peerKexAlgos); err != nil {
				msg.KexAlgos = retain(PRNG, msg.KexAlgos, peerKexAlgos[0])
			}

			peerCiphers := truncate(PeerPRNG, permute(PeerPRNG, preferredCiphers))
			if _, err := findCommon("", ciphers, peerCiphers); err != nil {
				ciphers = retain(PRNG, ciphers, peerCiphers[0])
				msg.CiphersClientServer = ciphers
				msg.CiphersServerClient = ciphers
			}

			peerMACs := supportedMACs
			if t.config.NoEncryptThenMACHash {
				peerMACs = noEncryptThenMACs
			}

			peerMACs = truncate(PeerPRNG, permute(PeerPRNG, peerMACs))
			if _, err := findCommon("", MACs, peerMACs); err != nil {
				MACs = retain(PRNG, MACs, peerMACs[0])
				msg.MACsClientServer = MACs
				msg.MACsServerClient = MACs
			}
		}

		// Offer "zlib@openssh.com", which is offered by OpenSSH. Compression
		// is not actually implemented, but since "zlib@openssh.com"
		// compression is delayed until after authentication
		// (https://www.openssh.com/txt/draft-miller-secsh-compression-
		// delayed-00.txt), an unauthenticated probe of the SSH server will
		// not detect this. "none" is always included to ensure negotiation
		// succeeds.
		if PRNG.FlipCoin() {
			compressions := permute(PRNG, []string{"none", "zlib@openssh.com"})
			msg.CompressionClientServer = compressions
			msg.CompressionServerClient = compressions
		}
	}

	packet := Marshal(msg)

	// writePacket destroys the contents, so save a copy.
	packetCopy := make([]byte, len(packet))
	copy(packetCopy, packet)

	if err := t.pushPacket(packetCopy); err != nil {
		return err
	}

	t.sentInitMsg = msg
	t.sentInitPacket = packet

	return nil
}

func (t *handshakeTransport) writePacket(p []byte) error {
	switch p[0] {
	case msgKexInit:
		return errors.New("ssh: only handshakeTransport can send kexInit")
	case msgNewKeys:
		return errors.New("ssh: only handshakeTransport can send newKeys")
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.writeError != nil {
		return t.writeError
	}

	if t.sentInitMsg != nil {
		// Copy the packet so the writer can reuse the buffer.
		cp := make([]byte, len(p))
		copy(cp, p)
		t.pendingPackets = append(t.pendingPackets, cp)
		return nil
	}

	if t.writeBytesLeft > 0 {
		t.writeBytesLeft -= int64(len(p))
	} else {
		t.requestKeyExchange()
	}

	if t.writePacketsLeft > 0 {
		t.writePacketsLeft--
	} else {
		t.requestKeyExchange()
	}

	if err := t.pushPacket(p); err != nil {
		t.writeError = err
	}

	return nil
}

func (t *handshakeTransport) Close() error {
	return t.conn.Close()
}

func (t *handshakeTransport) enterKeyExchange(otherInitPacket []byte) error {
	if debugHandshake {
		log.Printf("%s entered key exchange", t.id())
	}

	otherInit := &kexInitMsg{}
	if err := Unmarshal(otherInitPacket, otherInit); err != nil {
		return err
	}

	magics := handshakeMagics{
		clientVersion: t.clientVersion,
		serverVersion: t.serverVersion,
		clientKexInit: otherInitPacket,
		serverKexInit: t.sentInitPacket,
	}

	clientInit := otherInit
	serverInit := t.sentInitMsg
	if len(t.hostKeys) == 0 {
		clientInit, serverInit = serverInit, clientInit

		magics.clientKexInit = t.sentInitPacket
		magics.serverKexInit = otherInitPacket
	}

	var err error
	t.algorithms, err = findAgreedAlgorithms(clientInit, serverInit)
	if err != nil {
		return err
	}

	// We don't send FirstKexFollows, but we handle receiving it.
	//
	// RFC 4253 section 7 defines the kex and the agreement method for
	// first_kex_packet_follows. It states that the guessed packet
	// should be ignored if the "kex algorithm and/or the host
	// key algorithm is guessed wrong (server and client have
	// different preferred algorithm), or if any of the other
	// algorithms cannot be agreed upon". The other algorithms have
	// already been checked above so the kex algorithm and host key
	// algorithm are checked here.
	if otherInit.FirstKexFollows && (clientInit.KexAlgos[0] != serverInit.KexAlgos[0] || clientInit.ServerHostKeyAlgos[0] != serverInit.ServerHostKeyAlgos[0]) {
		// other side sent a kex message for the wrong algorithm,
		// which we have to ignore.
		if _, err := t.conn.readPacket(); err != nil {
			return err
		}
	}

	kex, ok := kexAlgoMap[t.algorithms.kex]
	if !ok {
		return fmt.Errorf("ssh: unexpected key exchange algorithm %v", t.algorithms.kex)
	}

	var result *kexResult
	if len(t.hostKeys) > 0 {
		result, err = t.server(kex, t.algorithms, &magics)
	} else {
		result, err = t.client(kex, t.algorithms, &magics)
	}

	if err != nil {
		return err
	}

	if t.sessionID == nil {
		t.sessionID = result.H
	}
	result.SessionID = t.sessionID

	if err := t.conn.prepareKeyChange(t.algorithms, result); err != nil {
		return err
	}
	if err = t.conn.writePacket([]byte{msgNewKeys}); err != nil {
		return err
	}
	if packet, err := t.conn.readPacket(); err != nil {
		return err
	} else if packet[0] != msgNewKeys {
		return unexpectedMessageError(msgNewKeys, packet[0])
	}

	return nil
}

func (t *handshakeTransport) server(kex kexAlgorithm, algs *algorithms, magics *handshakeMagics) (*kexResult, error) {
	var hostKey Signer
	for _, k := range t.hostKeys {
		if algs.hostKey == k.PublicKey().Type() {
			hostKey = k
		}
	}

	r, err := kex.Server(t.conn, t.config.Rand, magics, hostKey)
	return r, err
}

func (t *handshakeTransport) client(kex kexAlgorithm, algs *algorithms, magics *handshakeMagics) (*kexResult, error) {
	result, err := kex.Client(t.conn, t.config.Rand, magics)
	if err != nil {
		return nil, err
	}

	hostKey, err := ParsePublicKey(result.HostKey)
	if err != nil {
		return nil, err
	}

	if err := verifyHostKeySignature(hostKey, result); err != nil {
		return nil, err
	}

	err = t.hostKeyCallback(t.dialAddress, t.remoteAddr, hostKey)
	if err != nil {
		return nil, err
	}

	return result, nil
}
