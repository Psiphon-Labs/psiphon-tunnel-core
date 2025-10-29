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
	"strings"
	"sync"

	// [Psiphon]

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
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

// maxPendingPackets sets the maximum number of packets to queue while waiting
// for KEX to complete. This limits the total pending data to maxPendingPackets
// * maxPacket bytes, which is ~16.8MB.
const maxPendingPackets = 64

// keyingTransport is a packet based transport that supports key
// changes. It need not be thread-safe. It should pass through
// msgNewKeys in both directions.
type keyingTransport interface {
	packetConn

	// prepareKeyChange sets up a key change. The key change for a
	// direction will be effected if a msgNewKeys message is sent
	// or received.
	prepareKeyChange(*algorithms, *kexResult) error

	// setStrictMode sets the strict KEX mode, notably triggering
	// sequence number resets on sending or receiving msgNewKeys.
	// If the sequence number is already > 1 when setStrictMode
	// is called, an error is returned.
	setStrictMode() error

	// setInitialKEXDone indicates to the transport that the initial key exchange
	// was completed
	setInitialKEXDone()
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

	// publicKeyAuthAlgorithms is non-empty if we are the server. In that case,
	// it contains the supported client public key authentication algorithms.
	publicKeyAuthAlgorithms []string

	// hostKeyAlgorithms is non-empty if we are the client. In that case,
	// we accept these key types from the server as host key.
	hostKeyAlgorithms []string

	// On read error, incoming is closed, and readError is set.
	incoming  chan []byte
	readError error

	mu sync.Mutex
	// Condition for the above mutex. It is used to notify a completed key
	// exchange or a write failure. Writes can wait for this condition while a
	// key exchange is in progress.
	writeCond      *sync.Cond
	writeError     error
	sentInitPacket []byte
	sentInitMsg    *kexInitMsg
	// Used to queue writes when a key exchange is in progress. The length is
	// limited by pendingPacketsSize. Once full, writes will block until the key
	// exchange is completed or an error occurs. If not empty, it is emptied
	// all at once when the key exchange is completed in kexLoop.
	pendingPackets   [][]byte
	writePacketsLeft uint32
	writeBytesLeft   int64
	userAuthComplete bool // whether the user authentication phase is complete

	// If the read loop wants to schedule a kex, it pings this
	// channel, and the write loop will send out a kex
	// message.
	requestKex chan struct{}

	// If the other side requests or confirms a kex, its kexInit
	// packet is sent here for the write loop to find it.
	startKex    chan *pendingKex
	kexLoopDone chan struct{} // closed (with writeError non-nil) when kexLoop exits

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

	// Counters exclusively owned by readLoop.
	readPacketsLeft uint32
	readBytesLeft   int64

	// The session ID or nil if first kex did not complete yet.
	sessionID []byte

	// strictMode indicates if the other side of the handshake indicated
	// that we should be following the strict KEX protocol restrictions.
	strictMode bool

	// [Psiphon]
	// Unblocks readLoop blocked on sending to incoming channel.
	doSignalCloseReadLoop sync.Once
	signalCloseReadLoop   chan struct{}
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
		startKex:      make(chan *pendingKex),
		kexLoopDone:   make(chan struct{}),

		// [Psiphon]
		signalCloseReadLoop: make(chan struct{}),

		config: config,
	}
	t.writeCond = sync.NewCond(&t.mu)
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
	t.publicKeyAuthAlgorithms = config.PublicKeyAuthAlgorithms
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
		// If this is the first kex, and strict KEX mode is enabled,
		// we don't ignore any messages, as they may be used to manipulate
		// the packet sequence numbers.
		if !(t.sessionID == nil && t.strictMode) && (p[0] == msgIgnore || p[0] == msgDebug) {
			continue
		}

		// [Psiphon]
		// Add a closed signal case to interrupt readLoop when blocked on
		// sending to incoming.
		closed := false
		select {
		case t.incoming <- p:
		case <-t.signalCloseReadLoop:
			closed = true
		}
		if closed {
			t.readError = io.EOF
			close(t.incoming)
			break
		}
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
		t.writeCond.Broadcast()
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
		// Unblock writePacket if waiting for KEX.
		t.writeCond.Broadcast()
		t.mu.Unlock()
	}

	// Unblock reader.
	t.conn.Close()

	// drain startKex channel. We don't service t.requestKex
	// because nobody does blocking sends there.
	for request := range t.startKex {
		request.done <- t.getWriteError()
	}

	// Mark that the loop is done so that Close can return.
	close(t.kexLoopDone)
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

const (
	kexStrictClient = "kex-strict-c-v00@openssh.com"
	kexStrictServer = "kex-strict-s-v00@openssh.com"
)

// [Psiphon]
// For testing only. Enables testing support for legacy clients, which have
// only the legacy algorithm lists and no weak-MAC or new-server-algos logic.
// Not safe for concurrent access.
var testLegacyClient = false

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
		CiphersClientServer:     t.config.Ciphers,
		CiphersServerClient:     t.config.Ciphers,
		MACsClientServer:        t.config.MACs,
		MACsServerClient:        t.config.MACs,
		CompressionClientServer: supportedCompressions,
		CompressionServerClient: supportedCompressions,
	}
	io.ReadFull(rand.Reader, msg.Cookie[:])

	// We mutate the KexAlgos slice, in order to add the kex-strict extension algorithm,
	// and possibly to add the ext-info extension algorithm. Since the slice may be the
	// user owned KeyExchanges, we create our own slice in order to avoid using user
	// owned memory by mistake.
	msg.KexAlgos = make([]string, 0, len(t.config.KeyExchanges)+2) // room for kex-strict and ext-info
	msg.KexAlgos = append(msg.KexAlgos, t.config.KeyExchanges...)

	isServer := len(t.hostKeys) > 0
	if isServer {
		for _, k := range t.hostKeys {
			// If k is a MultiAlgorithmSigner, we restrict the signature
			// algorithms. If k is a AlgorithmSigner, presume it supports all
			// signature algorithms associated with the key format. If k is not
			// an AlgorithmSigner, we can only assume it only supports the
			// algorithms that matches the key format. (This means that Sign
			// can't pick a different default).
			keyFormat := k.PublicKey().Type()

			switch s := k.(type) {
			case MultiAlgorithmSigner:
				for _, algo := range algorithmsForKeyFormat(keyFormat) {
					if contains(s.Algorithms(), underlyingAlgo(algo)) {
						msg.ServerHostKeyAlgos = append(msg.ServerHostKeyAlgos, algo)
					}
				}
			case AlgorithmSigner:
				msg.ServerHostKeyAlgos = append(msg.ServerHostKeyAlgos, algorithmsForKeyFormat(keyFormat)...)
			default:
				msg.ServerHostKeyAlgos = append(msg.ServerHostKeyAlgos, keyFormat)
			}
		}

		if t.sessionID == nil {
			msg.KexAlgos = append(msg.KexAlgos, kexStrictServer)
		}
	} else {
		msg.ServerHostKeyAlgos = t.hostKeyAlgorithms

		// As a client we opt in to receiving SSH_MSG_EXT_INFO so we know what
		// algorithms the server supports for public key authentication. See RFC
		// 8308, Section 2.1.
		//
		// We also send the strict KEX mode extension algorithm, in order to opt
		// into the strict KEX mode.
		if firstKeyExchange := t.sessionID == nil; firstKeyExchange {
			msg.KexAlgos = append(msg.KexAlgos, "ext-info-c")
			msg.KexAlgos = append(msg.KexAlgos, kexStrictClient)
		}

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
	// When NoEncryptThenMACHash is specified, do not use Encrypt-then-MAC
	// hash algorithms.
	//
	// Limitations:
	//
	// - "ext-info-c" and "kex-strict-c/s-v00@openssh.com" extensions included
	//    in KexAlgos may be truncated; Psiphon's usage of SSH does not
	//    request SSH_MSG_EXT_INFO for client authentication and should not
	//    be vulnerable to downgrade attacks related to stripping
	//    SSH_MSG_EXT_INFO.
	//
	// - KEX algorithms are not synchronized with the version identification
	//   string.

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
		(!equal(t.config.KeyExchanges, preferredKexAlgos) ||
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
	noEncryptThenMACs := []string{"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", "hmac-sha1-96"}

	if t.config.NoEncryptThenMACHash {
		msg.MACsClientServer = noEncryptThenMACs
		msg.MACsServerClient = noEncryptThenMACs
	}

	if t.config.KEXPRNGSeed != nil {

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

		avoid := func(PRNG *prng.PRNG, list, avoidList, addList []string) []string {

			// Avoid negotiating items in avoidList, by moving a non-avoid
			// item to the front of the list; either by swapping with a
			// later, non-avoid item, or inserting a new item.

			if len(list) < 1 {
				return list
			}
			if !common.Contains(avoidList, list[0]) {
				// The first item isn't on the avoid list.
				return list
			}
			for i := 1; i < len(list); i++ {
				if !common.Contains(avoidList, list[i]) {
					// Swap with a later, existing non-avoid item.
					list[0], list[i] = list[i], list[0]
					return list
				}
			}
			for _, item := range permute(PRNG, addList) {
				if !common.Contains(avoidList, item) {
					// Insert a randomly selected non-avoid item.
					return append([]string{item}, list...)
				}
			}
			// Can't avoid.
			return list
		}

		addSome := func(PRNG *prng.PRNG, list, addList []string) []string {
			newList := list
			for _, item := range addList {
				if PRNG.FlipCoin() {
					index := PRNG.Range(0, len(newList))
					newList = append(
						newList[:index],
						append([]string{item}, newList[index:]...)...)
				}
			}
			return newList
		}

		toFront := func(list []string, item string) []string {
			for index, existingItem := range list {
				if existingItem == item {
					list[0], list[index] = list[index], list[0]
					return list
				}
			}
			return append([]string{item}, list...)
		}

		firstKexAlgo := func(kexAlgos []string) (string, bool) {
			for _, kexAlgo := range kexAlgos {
				switch kexAlgo {
				case "ext-info-c",
					"kex-strict-c-v00@openssh.com",
					"kex-strict-s-v00@openssh.com":
					// These extensions are not KEX algorithms
				default:
					return kexAlgo, true
				}
			}
			return "", false
		}

		selectKexAlgos := func(PRNG *prng.PRNG, kexAlgos []string) []string {
			kexAlgos = truncate(PRNG, permute(PRNG, kexAlgos))

			// Ensure an actual KEX algorithm is always selected
			if _, ok := firstKexAlgo(kexAlgos); ok {
				return kexAlgos
			}
			return retain(PRNG, kexAlgos, permute(PRNG, preferredKexAlgos)[0])
		}

		// Downgrade servers to use the algorithm lists used previously in
		// commits before 435a6a3f. This ensures that (a) the PeerKEXPRNGSeed
		// mechanism used in all existing clients correctly predicts the
		// server's algorithms; (b) random truncation by the server doesn't
		// select only new algorithms unknown to existing clients.
		//
		// New algorithms are then randomly inserted only after the legacy
		// lists are processed in legacy PRNG state order.

		legacyServerKexAlgos := []string{
			kexAlgoCurve25519SHA256LibSSH,
			kexAlgoECDH256, kexAlgoECDH384, kexAlgoECDH521,
			kexAlgoDH14SHA256, kexAlgoDH14SHA1,
		}
		legacyServerCiphers := []string{
			"aes128-gcm@openssh.com",
			chacha20Poly1305ID,
			"aes128-ctr", "aes192-ctr", "aes256-ctr",
		}
		legacyServerMACs := []string{
			"hmac-sha2-256-etm@openssh.com",
			"hmac-sha2-256", "hmac-sha1", "hmac-sha1-96",
		}
		legacyServerNoEncryptThenMACs := []string{
			"hmac-sha2-256", "hmac-sha1", "hmac-sha1-96",
		}
		if t.config.NoEncryptThenMACHash {
			legacyServerMACs = legacyServerNoEncryptThenMACs
		}

		PRNG := prng.NewPRNGWithSeed(t.config.KEXPRNGSeed)

		startingKexAlgos := msg.KexAlgos
		startingCiphers := msg.CiphersClientServer
		startingMACs := msg.MACsClientServer

		// testLegacyClient: legacy clients are older clients which start with
		// the same algorithm lists as legacyServer and have neither the
		// newServer-algorithm nor the weak-MAC KEX prediction logic.

		if isServer || testLegacyClient {
			startingKexAlgos = legacyServerKexAlgos
			startingCiphers = legacyServerCiphers
			startingMACs = legacyServerMACs
			if t.config.NoEncryptThenMACHash {
				startingMACs = legacyServerNoEncryptThenMACs
			}
		}

		kexAlgos := selectKexAlgos(PRNG, startingKexAlgos)

		ciphers := truncate(PRNG, permute(PRNG, startingCiphers))

		MACs := truncate(PRNG, permute(PRNG, startingMACs))

		var hostKeyAlgos []string
		if isServer {
			hostKeyAlgos = permute(PRNG, msg.ServerHostKeyAlgos)
		} else {
			// Must offer KeyAlgoRSA to Psiphon server.
			hostKeyAlgos = retain(
				PRNG,
				truncate(PRNG, permute(PRNG, msg.ServerHostKeyAlgos)),
				KeyAlgoRSA)
		}

		// To ensure compatibility with server KEX prediction in legacy
		// clients, all preceeding PRNG operations must be performed in the
		// given order, and all before the following operations.

		// Avoid negotiating weak MAC algorithms. Servers will ensure that no
		// weakMACs are the highest priority item. Clients will make
		// adjustments after predicting the server KEX.

		weakMACs := []string{"hmac-sha1-96"}

		if isServer {
			MACs = avoid(PRNG, MACs, weakMACs, startingMACs)
		}

		// Randomly insert new algorithms. For servers, the preceeding legacy
		// operations will ensure selection of at least one legacy algorithm
		// of each type, ensuring compatibility with legacy clients.

		newServerKexAlgos := []string{
			kexAlgoCurve25519SHA256, kexAlgoDH16SHA512,
			"kex-strict-s-v00@openssh.com",
		}
		newServerCiphers := []string{
			gcm256CipherID,
		}
		newServerMACs := []string{
			"hmac-sha2-512-etm@openssh.com", "hmac-sha2-512",
		}
		newServerNoEncryptThenMACs := []string{
			"hmac-sha2-512",
		}
		if t.config.NoEncryptThenMACHash {
			newServerMACs = newServerNoEncryptThenMACs
		}

		if isServer {
			kexAlgos = addSome(PRNG, kexAlgos, newServerKexAlgos)
			ciphers = addSome(PRNG, ciphers, newServerCiphers)
			MACs = addSome(PRNG, MACs, newServerMACs)
		}

		msg.KexAlgos = kexAlgos
		msg.CiphersClientServer = ciphers
		msg.CiphersServerClient = ciphers
		msg.MACsClientServer = MACs
		msg.MACsServerClient = MACs
		msg.ServerHostKeyAlgos = hostKeyAlgos

		if !isServer && t.config.PeerKEXPRNGSeed != nil {

			// Generate the server KEX and make adjustments if negotiation
			// would fail. This assumes that PeerKEXPRNGSeed remains static
			// (in Psiphon, the peer is the server and PeerKEXPRNGSeed is
			// derived from the server entry); and that the PRNG is invoked
			// in the exact same order on the server (i.e., the code block
			// immediately above is what the peer runs); and that the server
			// sets NoEncryptThenMACHash in the same cases.
			//
			// Note that only the client sends "ext-info-c"
			// and "kex-strict-c-v00@openssh.com" and only the server
			// sends "kex-strict-s-v00@openssh.com", so these will never
			// match and do not need to be filtered out before findCommon.

			PeerPRNG := prng.NewPRNGWithSeed(t.config.PeerKEXPRNGSeed)

			startingKexAlgos := legacyServerKexAlgos
			startingCiphers := legacyServerCiphers
			startingMACs := legacyServerMACs
			if t.config.NoEncryptThenMACHash {
				startingMACs = legacyServerNoEncryptThenMACs
			}

			// The server populates msg.ServerHostKeyAlgos based on the host
			// key type, which, for Psiphon servers, is "ssh-rsa", so
			// algorithmsForKeyFormat("ssh-rsa") predicts the server
			// msg.ServerHostKeyAlgos value.
			startingHostKeyAlgos := algorithmsForKeyFormat("ssh-rsa")

			serverKexAlgos := selectKexAlgos(PeerPRNG, startingKexAlgos)
			serverCiphers := truncate(PeerPRNG, permute(PeerPRNG, startingCiphers))
			serverMACs := truncate(PeerPRNG, permute(PeerPRNG, startingMACs))

			if !testLegacyClient {

				// This value is not used, but the identical PRNG operation must be
				// performed in order to predict the PeerPRNG state.
				_ = permute(PeerPRNG, startingHostKeyAlgos)

				serverMACs = avoid(PeerPRNG, serverMACs, weakMACs, startingMACs)

				serverKexAlgos = addSome(PeerPRNG, serverKexAlgos, newServerKexAlgos)
				serverCiphers = addSome(PeerPRNG, serverCiphers, newServerCiphers)
				serverMACs = addSome(PeerPRNG, serverMACs, newServerMACs)
			}

			// Adjust to ensure compatibility with the server KEX.

			if _, err := findCommon("", msg.KexAlgos, serverKexAlgos); err != nil {
				if kexAlgo, ok := firstKexAlgo(serverKexAlgos); ok {
					kexAlgos = retain(PRNG, msg.KexAlgos, kexAlgo)
				}
			}

			if _, err := findCommon("", ciphers, serverCiphers); err != nil {
				ciphers = retain(PRNG, ciphers, serverCiphers[0])
			}

			if _, err := findCommon("", MACs, serverMACs); err != nil {
				MACs = retain(PRNG, MACs, serverMACs[0])
			}

			// Avoid negotiating weak MAC algorithms.
			//
			// Legacy clients, without this logic, may still select only weak
			// MACs or predict only weak MACs for the server KEX.

			commonMAC, _ := findCommon("", MACs, serverMACs)
			if common.Contains(weakMACs, commonMAC) {
				// serverMACs[0] is not in weakMACs.
				MACs = toFront(MACs, serverMACs[0])
			}

			msg.KexAlgos = kexAlgos
			msg.CiphersClientServer = ciphers
			msg.CiphersServerClient = ciphers
			msg.MACsClientServer = MACs
			msg.MACsServerClient = MACs
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

var errSendBannerPhase = errors.New("ssh: SendAuthBanner outside of authentication phase")

func (t *handshakeTransport) writePacket(p []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch p[0] {
	case msgKexInit:
		return errors.New("ssh: only handshakeTransport can send kexInit")
	case msgNewKeys:
		return errors.New("ssh: only handshakeTransport can send newKeys")
	case msgUserAuthBanner:
		if t.userAuthComplete {
			return errSendBannerPhase
		}
	case msgUserAuthSuccess:
		t.userAuthComplete = true
	}

	if t.writeError != nil {
		return t.writeError
	}

	if t.sentInitMsg != nil {
		if len(t.pendingPackets) < maxPendingPackets {
			// Copy the packet so the writer can reuse the buffer.
			cp := make([]byte, len(p))
			copy(cp, p)
			t.pendingPackets = append(t.pendingPackets, cp)
			return nil
		}
		for t.sentInitMsg != nil {
			// Block and wait for KEX to complete or an error.
			t.writeCond.Wait()
			if t.writeError != nil {
				return t.writeError
			}
		}
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
		t.writeCond.Broadcast()
	}

	return nil
}

func (t *handshakeTransport) Close() error {
	// Close the connection. This should cause the readLoop goroutine to wake up
	// and close t.startKex, which will shut down kexLoop if running.
	err := t.conn.Close()

	// [Psiphon]
	// Interrupt any blocked readers or writers.
	t.interrupt(err)

	// Wait for the kexLoop goroutine to complete.
	// At that point we know that the readLoop goroutine is complete too,
	// because kexLoop itself waits for readLoop to close the startKex channel.
	<-t.kexLoopDone

	return err
}

// [Psiphon]
// interrupt unblocks any goroutines waiting on readLoop/writePacket when
// the underlying transport is shutting down and a KEX may be in progress.
func (t *handshakeTransport) interrupt(err error) {

	if err == nil {
		err = io.EOF
	}

	// Interrupt readLoop if blocked on sending to t.incoming.
	t.doSignalCloseReadLoop.Do(func() {
		close(t.signalCloseReadLoop)
	})

	// Interrupt writePacket if blocked on t.writeCond.Wait awaiting a KEX.
	// Call recordWriteError to ensure t.writeError is set, if not already;
	// and unconditionally Broadcast as well, in case the condition in
	// recordWriteError skips that.
	t.recordWriteError(err)
	t.writeCond.Broadcast()
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
	isClient := len(t.hostKeys) == 0
	if isClient {
		clientInit, serverInit = serverInit, clientInit

		magics.clientKexInit = t.sentInitPacket
		magics.serverKexInit = otherInitPacket
	}

	var err error
	t.algorithms, err = findAgreedAlgorithms(isClient, clientInit, serverInit)
	if err != nil {
		return err
	}

	if t.sessionID == nil && ((isClient && contains(serverInit.KexAlgos, kexStrictServer)) || (!isClient && contains(clientInit.KexAlgos, kexStrictClient))) &&

		// [Psiphon]
		// When KEX randomization omits "kex-strict-c/s-v00@openssh.com"
		// (see comment in sendKexInit), do not enable strict mode.
		((isClient && contains(t.sentInitMsg.KexAlgos, kexStrictClient)) || (!isClient && contains(t.sentInitMsg.KexAlgos, kexStrictServer))) {

		t.strictMode = true
		if err := t.conn.setStrictMode(); err != nil {
			return err
		}
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
		result, err = t.server(kex, &magics)
	} else {
		result, err = t.client(kex, &magics)
	}

	if err != nil {
		return err
	}

	firstKeyExchange := t.sessionID == nil
	if firstKeyExchange {
		t.sessionID = result.H
	}
	result.SessionID = t.sessionID

	if err := t.conn.prepareKeyChange(t.algorithms, result); err != nil {
		return err
	}
	if err = t.conn.writePacket([]byte{msgNewKeys}); err != nil {
		return err
	}

	// On the server side, after the first SSH_MSG_NEWKEYS, send a SSH_MSG_EXT_INFO
	// message with the server-sig-algs extension if the client supports it. See
	// RFC 8308, Sections 2.4 and 3.1, and [PROTOCOL], Section 1.9.
	if !isClient && firstKeyExchange && contains(clientInit.KexAlgos, "ext-info-c") {
		supportedPubKeyAuthAlgosList := strings.Join(t.publicKeyAuthAlgorithms, ",")
		extInfo := &extInfoMsg{
			NumExtensions: 2,
			Payload:       make([]byte, 0, 4+15+4+len(supportedPubKeyAuthAlgosList)+4+16+4+1),
		}
		extInfo.Payload = appendInt(extInfo.Payload, len("server-sig-algs"))
		extInfo.Payload = append(extInfo.Payload, "server-sig-algs"...)
		extInfo.Payload = appendInt(extInfo.Payload, len(supportedPubKeyAuthAlgosList))
		extInfo.Payload = append(extInfo.Payload, supportedPubKeyAuthAlgosList...)
		extInfo.Payload = appendInt(extInfo.Payload, len("ping@openssh.com"))
		extInfo.Payload = append(extInfo.Payload, "ping@openssh.com"...)
		extInfo.Payload = appendInt(extInfo.Payload, 1)
		extInfo.Payload = append(extInfo.Payload, "0"...)
		if err := t.conn.writePacket(Marshal(extInfo)); err != nil {
			return err
		}
	}

	if packet, err := t.conn.readPacket(); err != nil {
		return err
	} else if packet[0] != msgNewKeys {
		return unexpectedMessageError(msgNewKeys, packet[0])
	}

	if firstKeyExchange {
		// Indicates to the transport that the first key exchange is completed
		// after receiving SSH_MSG_NEWKEYS.
		t.conn.setInitialKEXDone()
	}

	return nil
}

// algorithmSignerWrapper is an AlgorithmSigner that only supports the default
// key format algorithm.
//
// This is technically a violation of the AlgorithmSigner interface, but it
// should be unreachable given where we use this. Anyway, at least it returns an
// error instead of panicing or producing an incorrect signature.
type algorithmSignerWrapper struct {
	Signer
}

func (a algorithmSignerWrapper) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*Signature, error) {
	if algorithm != underlyingAlgo(a.PublicKey().Type()) {
		return nil, errors.New("ssh: internal error: algorithmSignerWrapper invoked with non-default algorithm")
	}
	return a.Sign(rand, data)
}

func pickHostKey(hostKeys []Signer, algo string) AlgorithmSigner {
	for _, k := range hostKeys {
		if s, ok := k.(MultiAlgorithmSigner); ok {
			if !contains(s.Algorithms(), underlyingAlgo(algo)) {
				continue
			}
		}

		if algo == k.PublicKey().Type() {
			return algorithmSignerWrapper{k}
		}

		k, ok := k.(AlgorithmSigner)
		if !ok {
			continue
		}
		for _, a := range algorithmsForKeyFormat(k.PublicKey().Type()) {
			if algo == a {
				return k
			}
		}
	}
	return nil
}

func (t *handshakeTransport) server(kex kexAlgorithm, magics *handshakeMagics) (*kexResult, error) {
	hostKey := pickHostKey(t.hostKeys, t.algorithms.hostKey)
	if hostKey == nil {
		return nil, errors.New("ssh: internal error: negotiated unsupported signature type")
	}

	r, err := kex.Server(t.conn, t.config.Rand, magics, hostKey, t.algorithms.hostKey)
	return r, err
}

func (t *handshakeTransport) client(kex kexAlgorithm, magics *handshakeMagics) (*kexResult, error) {
	result, err := kex.Client(t.conn, t.config.Rand, magics)
	if err != nil {
		return nil, err
	}

	hostKey, err := ParsePublicKey(result.HostKey)
	if err != nil {
		return nil, err
	}

	if err := verifyHostKeySignature(hostKey, t.algorithms.hostKey, result); err != nil {
		return nil, err
	}

	err = t.hostKeyCallback(t.dialAddress, t.remoteAddr, hostKey)
	if err != nil {
		return nil, err
	}

	return result, nil
}
