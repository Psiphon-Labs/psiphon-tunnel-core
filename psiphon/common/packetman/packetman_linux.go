/*
 * Copyright (c) 2020, Psiphon Inc.
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

package packetman

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	cache "github.com/patrickmn/go-cache"
)

func IsSupported() bool {
	return true
}

const (
	netlinkSocketIOTimeout = 10 * time.Millisecond
	defaultSocketMark      = 0x70736970 // "PSIP"
	appliedSpecCacheTTL    = 1 * time.Minute
)

// Manipulator is a SYN-ACK packet manipulator.
//
// NFQUEUE/Netlink is used to intercept SYN-ACK packets, on all local
// interfaces, with source port equal to one of the ProtocolPorts specified in
// Config. For each intercepted SYN-ACK packet, the GetSpecName callback in
// Config is invoked; the callback determines which packet transformation spec
// to apply, based on, for example, client GeoIP, protocol, or other
// considerations.
//
// Protocol network listeners use GetAppliedSpecName to determine which
// transformation spec was applied to a given accepted connection.
//
// When a manipulations are to be applied to a SYN-ACK packet, NFQUEUE is
// instructed to drop the packet and one or more new packets, created by
// applying transformations to the original SYN-ACK packet, are injected via
// raw sockets. Raw sockets are used as NFQUEUE supports only replacing the
// original packet with one alternative packet.
//
// To avoid an intercept loop, injected packets are marked (SO_MARK) and the
// filter for NFQUEUE excludes packets with this mark.
//
// To avoid breaking TCP in unexpected cases, Manipulator fails open --
// allowing the original packet to proceed -- when packet parsing fails. For
// the same reason, the queue-bypass NFQUEUE option is set.
//
// As an iptables filter ensures only SYN-ACK packets are sent to the
// NFQUEUEs, the overhead of packet interception, parsing, and injection is
// incurred no more than once per TCP connection.
//
// NFQUEUE with queue-bypass requires Linux kernel 2.6.39; 3.16 or later is
// validated and recommended.
type Manipulator struct {
	config           *Config
	mutex            sync.Mutex
	runContext       context.Context
	stopRunning      context.CancelFunc
	waitGroup        *sync.WaitGroup
	injectIPv4FD     int
	injectIPv6FD     int
	nfqueue          *nfqueue.Nfqueue
	compiledSpecs    map[string]*compiledSpec
	appliedSpecCache *cache.Cache
}

// NewManipulator creates a new Manipulator.
func NewManipulator(config *Config) (*Manipulator, error) {

	compiledSpecs := make(map[string]*compiledSpec)

	for _, spec := range config.Specs {
		if spec.Name == "" {
			return nil, errors.TraceNew("invalid spec name")
		}
		if _, ok := compiledSpecs[spec.Name]; ok {
			return nil, errors.TraceNew("duplicate spec name")
		}
		compiledSpec, err := compileSpec(spec)
		if err != nil {
			return nil, errors.Trace(err)
		}
		compiledSpecs[spec.Name] = compiledSpec
	}

	// To avoid memory exhaustion, do not retain unconsumed appliedSpecCache
	// entries for a longer time than it may reasonably take to complete the TCP
	// handshake.
	appliedSpecCache := cache.New(appliedSpecCacheTTL, appliedSpecCacheTTL/2)

	return &Manipulator{
		config:           config,
		compiledSpecs:    compiledSpecs,
		appliedSpecCache: appliedSpecCache,
	}, nil
}

// Start initializes NFQUEUEs and raw sockets for packet manipulation. Start
// returns when initialization is complete; once it returns, the caller may
// assume that any SYN-ACK packets on configured ports will be intercepted. In
// the case of initialization failure, Start will undo any partial
// initialization. When Start succeeds, the caller must call Stop to free
// resources and restore networking state.
func (m *Manipulator) Start() (retErr error) {

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.runContext != nil {
		return errors.TraceNew("already running")
	}

	err := m.configureIPTables(true)
	if err != nil {
		return errors.Trace(err)
	}
	defer func() {
		if retErr != nil {
			m.configureIPTables(false)
		}
	}()

	m.injectIPv4FD, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return errors.Trace(err)
	}
	defer func() {
		if retErr != nil {
			syscall.Close(m.injectIPv4FD)
		}
	}()

	err = syscall.SetsockoptInt(m.injectIPv4FD, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return errors.Trace(err)
	}

	err = syscall.SetsockoptInt(m.injectIPv4FD, syscall.SOL_SOCKET, syscall.SO_MARK, m.getSocketMark())
	if err != nil {
		return errors.Trace(err)
	}

	m.injectIPv6FD, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil && !m.config.AllowNoIPv6NetworkConfiguration {
		return errors.Trace(err)
	}
	defer func() {
		if retErr != nil {
			syscall.Close(m.injectIPv6FD)
		}
	}()

	if m.injectIPv6FD != 0 {
		err = syscall.SetsockoptInt(m.injectIPv6FD, syscall.IPPROTO_IPV6, syscall.IP_HDRINCL, 1)
		if err != nil {
			// There's no AllowNoIPv6NetworkConfiguration in this case: if we can
			// create an IPv6 socket, we must be able to set its options.
			return errors.Trace(err)
		}

		err = syscall.SetsockoptInt(m.injectIPv6FD, syscall.SOL_SOCKET, syscall.SO_MARK, m.getSocketMark())
		if err != nil {
			return errors.Trace(err)
		}
	}

	// Use a reasonable buffer size to avoid excess allocation. As we're
	// intercepting only locally generated SYN-ACK packets, which should have no
	// payload, this size should be more than sufficient.
	maxPacketLen := uint32(1500)

	// Use the kernel default of 1024:
	// https://github.com/torvalds/linux/blob/cd8dead0c39457e58ec1d36db93aedca811d48f1/net/netfilter/nfnetlink_queue.c#L51,
	// via https://github.com/florianl/go-nfqueue/issues/3.
	maxQueueLen := uint32(1024)

	// Note: runContext alone is not sufficient to interrupt the
	// nfqueue.socketCallback goroutine spawned by nfqueue.Register; timeouts
	// must be set. See comment in Manipulator.Stop.

	m.nfqueue, err = nfqueue.Open(
		&nfqueue.Config{
			NfQueue:      uint16(m.config.QueueNumber),
			MaxPacketLen: maxPacketLen,
			MaxQueueLen:  maxQueueLen,
			Copymode:     nfqueue.NfQnlCopyPacket,
			Logger:       newNfqueueLogger(m.config.Logger),
			ReadTimeout:  netlinkSocketIOTimeout,
			WriteTimeout: netlinkSocketIOTimeout,
		})
	if err != nil {
		return errors.Trace(err)
	}
	defer func() {
		if retErr != nil {
			m.nfqueue.Close()
		}
	}()

	runContext, stopRunning := context.WithCancel(context.Background())
	defer func() {
		if retErr != nil {
			stopRunning()
		}
	}()

	err = m.nfqueue.Register(runContext, m.handleInterceptedPacket)
	if err != nil {
		return errors.Trace(err)
	}

	m.runContext = runContext
	m.stopRunning = stopRunning

	return nil
}

// Stop halts packet manipulation, frees resources, and restores networking
// state.
func (m *Manipulator) Stop() {

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.runContext == nil {
		return
	}

	m.stopRunning()

	// stopRunning will cancel the context passed into nfqueue.Register. The
	// goroutine spawned by Register, nfqueue.socketCallback, polls the context
	// after a read timeout:
	// https://github.com/florianl/go-nfqueue/blob/1e38df738c06deffbac08da8fec4b7c28a69b918/nfqueue_gteq_1.12.go#L138-L146
	//
	// There's no stop synchronization exposed by nfqueue. Calling nfqueue.Close
	// while socketCallback is still running can result in errors such as
	// "nfqueuenfqueue_gteq_1.12.go:134: Could not unbind from queue: netlink
	// send: sendmsg: bad file descriptor".
	//
	// To avoid invalid file descriptor operations and spurious error messages,
	// sleep for two polling periods, which should be sufficient, in most cases,
	// for socketCallback to poll the context and exit.

	time.Sleep(2 * netlinkSocketIOTimeout)

	m.nfqueue.Close()

	syscall.Close(m.injectIPv4FD)

	if m.injectIPv6FD != 0 {
		syscall.Close(m.injectIPv6FD)
	}

	m.configureIPTables(false)
}

func makeConnectionID(
	srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) string {

	// Create a unique connection ID, for appliedSpecCache, from the 4-tuple
	// srcIP, dstIP, srcPort, dstPort. In the SYN/ACK context, src is the server
	// and dst is the client.
	//
	// Limitation: there may be many repeat connections from one dstIP,
	// especially if many clients are behind the same NAT. Each TCP connection
	// will have a distinct dstPort. In principle, there remains a race between
	// populating appliedSpecCache, the TCP connection terminating on the
	// client-side and the NAT reusing the dstPort, and consuming
	// appliedSpecCache.

	// From: https://github.com/golang/go/blob/b88efc7e7ac15f9e0b5d8d9c82f870294f6a3839/src/net/ip.go#L55
	var v4InV6Prefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}
	const uint16Len = 2

	var connID [net.IPv6len + uint16Len + net.IPv6len + uint16Len]byte

	offset := 0
	if len(srcIP) == net.IPv4len {
		copy(connID[offset:], v4InV6Prefix)
		offset += len(v4InV6Prefix)
		copy(connID[offset:], srcIP)
		offset += len(srcIP)
	} else { // net.IPv6len
		copy(connID[offset:], srcIP)
		offset += len(srcIP)
	}
	binary.BigEndian.PutUint16(connID[offset:], srcPort)
	offset += uint16Len

	if len(dstIP) == net.IPv4len {
		copy(connID[offset:], v4InV6Prefix)
		offset += len(v4InV6Prefix)
		copy(connID[offset:], dstIP)
		offset += len(dstIP)
	} else { // net.IPv6len
		copy(connID[offset:], dstIP)
		offset += len(dstIP)
	}
	binary.BigEndian.PutUint16(connID[offset:], dstPort)
	offset += uint16Len

	return string(connID[:])
}

// GetAppliedSpecName returns the packet manipulation spec name applied to the
// TCP connection, represented by its local and remote address components,
// that was ultimately accepted by a network listener.
//
// This allows GetSpecName, the spec selector, to be non-deterministic while
// also allowing for accurate packet manipulation metrics to be associated
// with each TCP connection.
//
// For a given connection, GetAppliedSpecName must be called before a TTL
// clears the stored value. Calling GetAppliedSpecName immediately clears the
// stored value for the given connection.
//
// To obtain the correct result GetAppliedSpecName must be called with a
// RemoteAddr which reflects the true immediate network peer address. In
// particular, for proxied net.Conns which present a synthetic RemoteAddr with
// the original address of a proxied client (e.g., armon/go-proxyproto, or
// psiphon/server.meekConn) the true peer RemoteAddr must instead be
// provided.
func (m *Manipulator) GetAppliedSpecName(
	localAddr, remoteAddr *net.TCPAddr) (string, error) {

	connID := makeConnectionID(
		localAddr.IP,
		uint16(localAddr.Port),
		remoteAddr.IP,
		uint16(remoteAddr.Port))

	specName, found := m.appliedSpecCache.Get(connID)
	if !found {
		return "", errors.TraceNew("connection not found")
	}

	m.appliedSpecCache.Delete(connID)

	return specName.(string), nil
}

func (m *Manipulator) setAppliedSpecName(
	interceptedPacket gopacket.Packet, specName string) {

	srcIP, dstIP, _, _ := m.getPacketAddressInfo(interceptedPacket)

	interceptedTCP := interceptedPacket.Layer(layers.LayerTypeTCP).(*layers.TCP)

	connID := makeConnectionID(
		srcIP,
		uint16(interceptedTCP.SrcPort),
		dstIP,
		uint16(interceptedTCP.DstPort))

	m.appliedSpecCache.Set(connID, specName, cache.DefaultExpiration)
}

func (m *Manipulator) getSocketMark() int {
	if m.config.SocketMark == 0 {
		return defaultSocketMark
	}
	return m.config.SocketMark
}

func (m *Manipulator) handleInterceptedPacket(attr nfqueue.Attribute) int {

	if attr.PacketID == nil || attr.Payload == nil {
		m.config.Logger.WithTrace().Warning("missing nfqueue data")
		return 0
	}

	// Trigger packet manipulation only if the packet is a SYN-ACK and has no
	// payload (which a transformation _may_ discard). The iptables filter for
	// NFQUEUE should already ensure that only SYN-ACK packets are sent through
	// the queue. To avoid breaking all TCP connections in an unanticipated case,
	// fail open -- allow the packet -- if these conditions are not met or if
	// parsing the packet fails.

	packet, err := m.parseInterceptedPacket(*attr.Payload)
	if err != nil {

		// Fail open in this case.
		m.nfqueue.SetVerdict(*attr.PacketID, nfqueue.NfAccept)

		m.config.Logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("unexpected packet")
		return 0
	}

	spec, err := m.getCompiledSpec(packet)
	if err != nil {

		// Fail open in this case.
		m.nfqueue.SetVerdict(*attr.PacketID, nfqueue.NfAccept)

		m.config.Logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("get strategy failed")
		return 0
	}

	// Call setAppliedSpecName cache _before_ accepting the packet or injecting
	// manipulated packets to avoid a potential race in which the TCP handshake
	// completes and GetAppliedSpecName is called before the cache is populated.

	if spec == nil {

		// No packet manipulation in this case.
		m.setAppliedSpecName(packet, "")
		m.nfqueue.SetVerdict(*attr.PacketID, nfqueue.NfAccept)
		return 0
	}

	m.setAppliedSpecName(packet, spec.name)
	m.nfqueue.SetVerdict(*attr.PacketID, nfqueue.NfDrop)

	err = m.injectPackets(packet, spec)
	if err != nil {
		m.config.Logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("inject packets failed")
		return 0
	}

	return 0
}

func (m *Manipulator) parseInterceptedPacket(packetData []byte) (gopacket.Packet, error) {

	// Note that NFQUEUE doesn't send an Ethernet layer. This first layer is
	// either IPv4 or IPv6.
	//
	// As we parse only one packet per TCP connection, we are not using the
	// faster DecodingLayerParser API,
	// https://godoc.org/github.com/google/gopacket#hdr-Fast_Decoding_With_DecodingLayerParser,
	// or zero-copy approaches.
	//
	// TODO: use a stub gopacket.Decoder as the first layer to avoid the extra
	// NewPacket call? Use distinct NFQUEUE queue numbers and nfqueue instances
	// for IPv4 and IPv6?

	packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

	if packet.ErrorLayer() != nil {
		packet = gopacket.NewPacket(packetData, layers.LayerTypeIPv6, gopacket.Default)
	}

	errLayer := packet.ErrorLayer()
	if errLayer != nil {
		return nil, errors.Trace(errLayer.Error())
	}

	// After this check, Layer([IPv4,IPv6]/TCP) return values are assumed to be
	// non-nil and unchecked layer type assertions are assumed safe.

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, errors.TraceNew("missing TCP layer")
	}

	if packet.Layer(gopacket.LayerTypePayload) != nil {
		return nil, errors.TraceNew("unexpected payload layer")
	}

	tcp := tcpLayer.(*layers.TCP)

	if !tcp.SYN || !tcp.ACK ||
		tcp.FIN || tcp.RST || tcp.PSH || tcp.URG || tcp.ECE || tcp.CWR || tcp.NS {
		return nil, errors.TraceNew("unexpected TCP flags")
	}

	stripEOLOption(packet)

	return packet, nil
}

func (m *Manipulator) getCompiledSpec(interceptedPacket gopacket.Packet) (*compiledSpec, error) {

	_, dstIP, _, _ := m.getPacketAddressInfo(interceptedPacket)

	interceptedTCP := interceptedPacket.Layer(layers.LayerTypeTCP).(*layers.TCP)

	protocolPort := interceptedTCP.SrcPort
	clientIP := dstIP

	specName := m.config.GetSpecName(int(protocolPort), clientIP)
	if specName == "" {
		return nil, nil
	}

	spec, ok := m.compiledSpecs[specName]
	if !ok {
		return nil, errors.Tracef("invalid spec name: %s", specName)
	}

	return spec, nil
}

func (m *Manipulator) injectPackets(interceptedPacket gopacket.Packet, spec *compiledSpec) error {

	// A sockAddr parameter with dstIP (but not port) set appears to be required
	// even with the IP_HDRINCL socket option.

	_, _, injectFD, sockAddr := m.getPacketAddressInfo(interceptedPacket)

	injectPackets, err := spec.apply(interceptedPacket)
	if err != nil {
		return errors.Trace(err)
	}

	for _, injectPacket := range injectPackets {

		err = syscall.Sendto(injectFD, injectPacket, 0, sockAddr)
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

func (m *Manipulator) getPacketAddressInfo(interceptedPacket gopacket.Packet) (net.IP, net.IP, int, syscall.Sockaddr) {

	var srcIP, dstIP net.IP
	var injectFD int
	var sockAddr syscall.Sockaddr

	ipv4Layer := interceptedPacket.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		interceptedIPv4 := ipv4Layer.(*layers.IPv4)
		srcIP = interceptedIPv4.SrcIP
		dstIP = interceptedIPv4.DstIP
		injectFD = m.injectIPv4FD
		var ipv4 [4]byte
		copy(ipv4[:], interceptedIPv4.DstIP.To4())
		sockAddr = &syscall.SockaddrInet4{Addr: ipv4, Port: 0}
	} else {
		interceptedIPv6 := interceptedPacket.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		srcIP = interceptedIPv6.SrcIP
		dstIP = interceptedIPv6.DstIP
		injectFD = m.injectIPv6FD
		var ipv6 [16]byte
		copy(ipv6[:], interceptedIPv6.DstIP.To16())
		sockAddr = &syscall.SockaddrInet6{Addr: ipv6, Port: 0}
	}

	return srcIP, dstIP, injectFD, sockAddr
}

func (m *Manipulator) configureIPTables(addRules bool) error {

	execCommands := func(mode string) error {

		ports := make([]string, len(m.config.ProtocolPorts))
		for i, port := range m.config.ProtocolPorts {
			ports[i] = strconv.Itoa(port)
		}

		socketMark := strconv.Itoa(m.getSocketMark())

		args := []string{
			mode, "OUTPUT",
			"--protocol", "tcp",
			"--match", "multiport",
			"--source-ports", strings.Join(ports, ","),
			"--match", "mark",
			"!", "--mark", socketMark,
			"--tcp-flags", "ALL", "SYN,ACK",
			"-j", "NFQUEUE",
			"--queue-bypass",
			"--queue-num", strconv.Itoa(m.config.QueueNumber),
		}

		err := common.RunNetworkConfigCommand(
			m.config.Logger,
			m.config.SudoNetworkConfigCommands,
			"iptables",
			args...)
		if mode != "-D" && err != nil {
			return errors.Trace(err)
		}

		err = common.RunNetworkConfigCommand(
			m.config.Logger,
			m.config.SudoNetworkConfigCommands,
			"ip6tables",
			args...)
		if mode != "-D" && err != nil {
			if m.config.AllowNoIPv6NetworkConfiguration {
				m.config.Logger.WithTraceFields(
					common.LogFields{
						"error": err}).Warning(
					"configure IPv6 NFQUEUE failed")
			} else {
				return errors.Trace(err)
			}
		}

		return nil
	}

	// To avoid duplicates, first try to drop existing rules, then add. Also try
	// to revert any partial configuration in the case of an error.

	_ = execCommands("-D")

	if addRules {
		err := execCommands("-I")
		if err != nil {
			_ = execCommands("-D")
		}
		return errors.Trace(err)
	}

	return nil
}

func newNfqueueLogger(logger common.Logger) *log.Logger {
	return log.New(
		&nfqueueLoggerWriter{logger: logger},
		"nfqueue",
		log.Lshortfile)
}

type nfqueueLoggerWriter struct {
	logger common.Logger
}

func (n *nfqueueLoggerWriter) Write(p []byte) (int, error) {
	n.logger.WithTraceFields(
		common.LogFields{"log": string(p)}).Warning("nfqueue log")
	return len(p), nil
}
