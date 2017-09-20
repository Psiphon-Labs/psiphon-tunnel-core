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

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

const (
	UNIX_DOMAIN_SOCKET_NAME = "/tmp/tun_test.sock"
	SESSION_ID_LENGTH       = 16
	TCP_PORT                = 8000
	TCP_RELAY_CHUNK_SIZE    = int64(65536)
	TCP_RELAY_TOTAL_SIZE    = int64(1073741824)
	CONCURRENT_CLIENT_COUNT = 5
	PACKET_METRICS_TIMEOUT  = 10 * time.Second
)

func TestTunneledTCPIPv4(t *testing.T) {
	testTunneledTCP(t, false)
}

func TestTunneledTCPIPv6(t *testing.T) {
	testTunneledTCP(t, true)
}

func TestTunneledDNS(t *testing.T) {
	t.Skip("TODO: test DNS tunneling")
}

func TestSessionExpiry(t *testing.T) {
	t.Skip("TODO: test short session TTLs actually persist/expire as expected")
}

func TestTrafficRules(t *testing.T) {
	t.Skip("TODO: negative tests for checkAllowedTCPPortFunc, checkAllowedUDPPortFunc")
}

func TestResetRouting(t *testing.T) {
	t.Skip("TODO: test conntrack delete effectiveness")
}

func testTunneledTCP(t *testing.T, useIPv6 bool) {

	// This test harness does the following:
	//
	// - starts a TCP server; this server echoes the data it receives
	// - starts a packet tunnel server that uses a unix domain socket for client channels
	// - starts CONCURRENT_CLIENT_COUNT concurrent clients
	// - each client runs a packet tunnel client connected to the server unix domain socket
	//   and establishes a TCP client connection to the TCP through the packet tunnel
	// - each TCP client transfers TCP_RELAY_TOTAL_SIZE bytes to the TCP server
	// - the test checks that all data echoes back correctly and that the server packet
	//   metrics reflects the expected amount of data transferred through the tunnel
	// - the test also checks that the flow activity updater mechanism correctly reports
	//   the total bytes transferred
	// - this test runs in either IPv4 or IPv6 mode
	// - the test host's public IP address is used as the TCP server IP address; it is
	//   expected that the server tun device will NAT to the public interface; clients
	//   use SO_BINDTODEVICE/IP_BOUND_IF to force the TCP client connections through the
	//   tunnel
	//
	// Note: this test can modify host network configuration; in addition to tun device
	// and routing config, see the changes made in fixBindToDevice.

	if TCP_RELAY_TOTAL_SIZE%TCP_RELAY_CHUNK_SIZE != 0 {
		t.Fatalf("startTestTCPServer failed: invalid relay size")
	}

	MTU := DEFAULT_MTU

	testTCPServer, err := startTestTCPServer(useIPv6)
	if err != nil {
		if err == errNoIPAddress {
			t.Skipf("test unsupported: %s", errNoIPAddress)
		}
		t.Fatalf("startTestTCPServer failed: %s", err)
	}

	var counter bytesTransferredCounter
	flowActivityUpdaterMaker := func(_ string, _ net.IP) []FlowActivityUpdater {
		return []FlowActivityUpdater{&counter}
	}

	testServer, err := startTestServer(useIPv6, MTU, flowActivityUpdaterMaker)
	if err != nil {
		t.Fatalf("startTestServer failed: %s", err)
	}

	results := make(chan error, CONCURRENT_CLIENT_COUNT)

	for i := 0; i < CONCURRENT_CLIENT_COUNT; i++ {
		go func() {

			testClient, err := startTestClient(
				useIPv6, MTU, []string{testTCPServer.getListenerIPAddress()})
			if err != nil {
				results <- fmt.Errorf("startTestClient failed: %s", err)
				return
			}

			// The TCP client will bind to the packet tunnel client tun
			// device and connect to the TCP server. With the bind to
			// device, TCP packets will flow through the packet tunnel
			// client to the packet tunnel server, through the packet tunnel
			// server's tun device, NATed to the server's public interface,
			// and finally reaching the TCP server. All this happens on
			// the single host running the test.

			testTCPClient, err := startTestTCPClient(
				testClient.tunClient.device.Name(),
				testTCPServer.getListenerIPAddress())
			if err != nil {
				results <- fmt.Errorf("startTestTCPClient failed: %s", err)
				return
			}

			// Send TCP_RELAY_TOTAL_SIZE random bytes to the TCP server, and
			// check that it echoes back the same bytes.

			sendChunk, receiveChunk := make([]byte, TCP_RELAY_CHUNK_SIZE), make([]byte, TCP_RELAY_CHUNK_SIZE)

			for i := int64(0); i < TCP_RELAY_TOTAL_SIZE; i += TCP_RELAY_CHUNK_SIZE {

				_, err := rand.Read(sendChunk)
				if err != nil {
					results <- fmt.Errorf("rand.Read failed: %s", err)
					return
				}

				_, err = testTCPClient.Write(sendChunk)
				if err != nil {
					results <- fmt.Errorf("mockTCPClient.Write failed: %s", err)
					return
				}

				_, err = io.ReadFull(testTCPClient, receiveChunk)
				if err != nil {
					results <- fmt.Errorf("io.ReadFull failed: %s", err)
					return
				}

				if 0 != bytes.Compare(sendChunk, receiveChunk) {
					results <- fmt.Errorf("bytes.Compare failed")
					return
				}
			}

			testTCPClient.stop()

			testClient.stop()

			// Check metrics to ensure traffic was tunneled and metrics reported

			// Note: this code does not ensure that the "last" packet metrics was
			// for this very client; but all packet metrics should be the same.

			packetMetricsFields := testServer.logger.getLastPacketMetrics()

			if packetMetricsFields == nil {
				results <- fmt.Errorf("testServer.logger.getLastPacketMetrics failed")
				return
			}

			expectedFields := []struct {
				nameSuffix   string
				minimumValue int64
			}{
				{"packets_up", TCP_RELAY_TOTAL_SIZE / int64(MTU)},
				{"packets_down", TCP_RELAY_TOTAL_SIZE / int64(MTU)},
				{"bytes_up", TCP_RELAY_TOTAL_SIZE},
				{"bytes_down", TCP_RELAY_TOTAL_SIZE},
			}

			for _, expectedField := range expectedFields {
				var name string
				if useIPv6 {
					name = "tcp_ipv6_" + expectedField.nameSuffix
				} else {
					name = "tcp_ipv4_" + expectedField.nameSuffix
				}
				field, ok := packetMetricsFields[name]
				if !ok {
					results <- fmt.Errorf("missing expected metric field: %s", name)
					return
				}
				value, ok := field.(int64)
				if !ok {
					results <- fmt.Errorf("unexpected metric field type: %s", name)
					return
				}
				if value < expectedField.minimumValue {
					results <- fmt.Errorf("unexpected metric field value: %s: %d", name, value)
					return
				}
			}

			results <- nil
		}()
	}

	for i := 0; i < CONCURRENT_CLIENT_COUNT; i++ {
		result := <-results
		if result != nil {
			t.Fatalf(result.Error())
		}
	}

	// Note: reported bytes transferred can exceed expected bytes
	// transferred due to retransmission of packets.

	upstreamBytesTransferred, downstreamBytesTransferred, _ := counter.Get()
	expectedBytesTransferred := CONCURRENT_CLIENT_COUNT * TCP_RELAY_TOTAL_SIZE
	if upstreamBytesTransferred < expectedBytesTransferred {
		t.Fatalf("unexpected upstreamBytesTransferred: %d; expected at least %d",
			upstreamBytesTransferred, expectedBytesTransferred)
	}
	if downstreamBytesTransferred < expectedBytesTransferred {
		t.Fatalf("unexpected downstreamBytesTransferred: %d; expected at least %d",
			downstreamBytesTransferred, expectedBytesTransferred)
	}

	testServer.stop()

	testTCPServer.stop()
}

type bytesTransferredCounter struct {
	// Note: 64-bit ints used with atomic operations are placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	upstreamBytes       int64
	downstreamBytes     int64
	durationNanoseconds int64
}

func (counter *bytesTransferredCounter) UpdateProgress(
	upstreamBytes, downstreamBytes int64, durationNanoseconds int64) {

	atomic.AddInt64(&counter.upstreamBytes, upstreamBytes)
	atomic.AddInt64(&counter.downstreamBytes, downstreamBytes)
	atomic.AddInt64(&counter.durationNanoseconds, durationNanoseconds)
}

func (counter *bytesTransferredCounter) Get() (int64, int64, int64) {
	return atomic.LoadInt64(&counter.upstreamBytes),
		atomic.LoadInt64(&counter.downstreamBytes),
		atomic.LoadInt64(&counter.durationNanoseconds)
}

type testServer struct {
	logger       *testLogger
	updaterMaker FlowActivityUpdaterMaker
	tunServer    *Server
	unixListener net.Listener
	clientConns  *common.Conns
	workers      *sync.WaitGroup
}

func startTestServer(
	useIPv6 bool, MTU int, updaterMaker FlowActivityUpdaterMaker) (*testServer, error) {

	logger := newTestLogger(true)

	noDNSResolvers := func() []net.IP { return make([]net.IP, 0) }

	config := &ServerConfig{
		Logger: logger,
		SudoNetworkConfigCommands:       os.Getenv("TUN_TEST_SUDO") != "",
		AllowNoIPv6NetworkConfiguration: !useIPv6,
		GetDNSResolverIPv4Addresses:     noDNSResolvers,
		GetDNSResolverIPv6Addresses:     noDNSResolvers,
		MTU: MTU,
	}

	tunServer, err := NewServer(config)
	if err != nil {
		return nil, fmt.Errorf("startTestServer(): NewServer failed: %s", err)
	}

	tunServer.Start()

	_ = syscall.Unlink(UNIX_DOMAIN_SOCKET_NAME)

	unixListener, err := net.Listen("unix", UNIX_DOMAIN_SOCKET_NAME)
	if err != nil {
		return nil, fmt.Errorf("startTestServer(): net.Listen failed: %s", err)
	}

	server := &testServer{
		logger:       logger,
		updaterMaker: updaterMaker,
		tunServer:    tunServer,
		unixListener: unixListener,
		clientConns:  new(common.Conns),
		workers:      new(sync.WaitGroup),
	}

	server.workers.Add(1)
	go server.run()

	return server, nil
}

func (server *testServer) run() {
	defer server.workers.Done()

	for {
		clientConn, err := server.unixListener.Accept()
		if err != nil {
			fmt.Printf("testServer.run(): unixListener.Accept failed: %s\n", err)
			return
		}

		signalConn := newSignalConn(clientConn)

		if !server.clientConns.Add(signalConn) {
			return
		}

		server.workers.Add(1)
		go func() {
			defer server.workers.Done()
			defer signalConn.Close()

			sessionID, err := common.MakeRandomStringHex(SESSION_ID_LENGTH)
			if err != nil {
				fmt.Printf("testServer.run(): common.MakeRandomStringHex failed: %s\n", err)
				return
			}

			checkAllowedPortFunc := func(net.IP, int) bool { return true }

			server.tunServer.ClientConnected(
				sessionID,
				signalConn,
				checkAllowedPortFunc,
				checkAllowedPortFunc,
				server.updaterMaker)

			signalConn.Wait()

			server.tunServer.ClientDisconnected(
				sessionID)
		}()
	}
}

func (server *testServer) stop() {
	server.clientConns.CloseAll()
	server.unixListener.Close()
	server.workers.Wait()
	server.tunServer.Stop()
}

type signalConn struct {
	net.Conn
	ioErrorSignal chan struct{}
}

func newSignalConn(baseConn net.Conn) *signalConn {
	return &signalConn{
		Conn:          baseConn,
		ioErrorSignal: make(chan struct{}, 1),
	}
}

func (conn *signalConn) Read(p []byte) (n int, err error) {
	n, err = conn.Conn.Read(p)
	if err != nil {
		_ = conn.Conn.Close()
		select {
		case conn.ioErrorSignal <- *new(struct{}):
		default:
		}
	}
	return
}

func (conn *signalConn) Write(p []byte) (n int, err error) {
	n, err = conn.Conn.Write(p)
	if err != nil {
		_ = conn.Conn.Close()
		select {
		case conn.ioErrorSignal <- *new(struct{}):
		default:
		}
	}
	return
}

func (conn *signalConn) Wait() {
	<-conn.ioErrorSignal
}

type testClient struct {
	logger    *testLogger
	unixConn  net.Conn
	tunClient *Client
}

func startTestClient(
	useIPv6 bool,
	MTU int,
	routeDestinations []string) (*testClient, error) {

	unixConn, err := net.Dial("unix", UNIX_DOMAIN_SOCKET_NAME)
	if err != nil {
		return nil, fmt.Errorf("startTestClient(): net.Dial failed: %s", err)
	}

	logger := newTestLogger(false)

	// Assumes IP addresses are available on test host

	config := &ClientConfig{
		Logger: logger,
		SudoNetworkConfigCommands:       os.Getenv("TUN_TEST_SUDO") != "",
		AllowNoIPv6NetworkConfiguration: !useIPv6,
		IPv4AddressCIDR:                 "172.16.0.1/24",
		IPv6AddressCIDR:                 "fd26:b6a6:4454:310a:0000:0000:0000:0001/64",
		RouteDestinations:               routeDestinations,
		Transport:                       unixConn,
		MTU:                             MTU,
	}

	tunClient, err := NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("startTestClient(): NewClient failed: %s", err)
	}

	// Configure kernel to fix issue described in fixBindToDevice

	err = fixBindToDevice(logger, config.SudoNetworkConfigCommands, tunClient.device.Name())
	if err != nil {
		return nil, fmt.Errorf("startTestClient(): fixBindToDevice failed: %s", err)
	}

	tunClient.Start()

	return &testClient{
		logger:    logger,
		unixConn:  unixConn,
		tunClient: tunClient,
	}, nil
}

func (client *testClient) stop() {
	client.unixConn.Close()
	client.tunClient.Stop()
}

type testTCPServer struct {
	listenerIPAddress string
	tcpListener       net.Listener
	clientConns       *common.Conns
	workers           *sync.WaitGroup
}

var errNoIPAddress = errors.New("no IP address")

func startTestTCPServer(useIPv6 bool) (*testTCPServer, error) {

	interfaceName := DEFAULT_PUBLIC_INTERFACE_NAME

	hostIPaddress := ""

	IPv4Address, IPv6Address, err := common.GetInterfaceIPAddresses(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("startTestTCPServer(): GetInterfaceIPAddresses failed: %s", err)
	}

	if useIPv6 {
		// Cannot route to link local address
		if IPv6Address == nil || IPv6Address.IsLinkLocalUnicast() {
			return nil, errNoIPAddress
		}
		hostIPaddress = IPv6Address.String()
	} else {
		if IPv4Address == nil || IPv4Address.IsLinkLocalUnicast() {
			return nil, errNoIPAddress
		}
		hostIPaddress = IPv4Address.String()
	}

	tcpListener, err := net.Listen("tcp", net.JoinHostPort(hostIPaddress, strconv.Itoa(TCP_PORT)))
	if err != nil {
		return nil, fmt.Errorf("startTestTCPServer(): net.Listen failed: %s", err)
	}

	server := &testTCPServer{
		listenerIPAddress: hostIPaddress,
		tcpListener:       tcpListener,
		clientConns:       new(common.Conns),
		workers:           new(sync.WaitGroup),
	}

	server.workers.Add(1)
	go server.run()

	return server, nil
}

func (server *testTCPServer) getListenerIPAddress() string {
	return server.listenerIPAddress
}

func (server *testTCPServer) run() {
	defer server.workers.Done()

	for {
		clientConn, err := server.tcpListener.Accept()
		if err != nil {
			fmt.Printf("testTCPServer.run(): tcpListener.Accept failed: %s\n", err)
			return
		}

		if !server.clientConns.Add(clientConn) {
			return
		}

		server.workers.Add(1)
		go func() {
			defer server.workers.Done()
			defer clientConn.Close()

			buffer := make([]byte, TCP_RELAY_CHUNK_SIZE)

			for {
				_, err := io.ReadFull(clientConn, buffer)
				if err != nil {
					fmt.Printf("testTCPServer.run(): io.ReadFull failed: %s\n", err)
					return
				}
				_, err = clientConn.Write(buffer)
				if err != nil {
					fmt.Printf("testTCPServer.run(): clientConn.Write failed: %s\n", err)
					return
				}
			}
		}()
	}
}

func (server *testTCPServer) stop() {
	server.clientConns.CloseAll()
	server.tcpListener.Close()
	server.workers.Wait()
}

type testTCPClient struct {
	conn net.Conn
}

func startTestTCPClient(
	tunDeviceName, serverIPAddress string) (*testTCPClient, error) {

	// This is a simplified version of the low-level TCP dial
	// code in psiphon/TCPConn, which supports BindToDevice.
	// It does not resolve domain names and does not have an
	// explicit timeout.

	var ipv4 [4]byte
	var ipv6 [16]byte
	var domain int
	var sockAddr syscall.Sockaddr

	ipAddr := net.ParseIP(serverIPAddress)
	if ipAddr == nil {
		return nil, fmt.Errorf("net.ParseIP failed")
	}

	if ipAddr.To4() != nil {
		copy(ipv4[:], ipAddr.To4())
		domain = syscall.AF_INET
		sockAddr = &syscall.SockaddrInet4{Addr: ipv4, Port: TCP_PORT}
	} else {
		copy(ipv6[:], ipAddr.To16())
		domain = syscall.AF_INET6
		sockAddr = &syscall.SockaddrInet6{Addr: ipv6, Port: TCP_PORT}
	}

	socketFd, err := syscall.Socket(domain, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("syscall.Socket failed: %s", err)
	}

	err = BindToDevice(socketFd, tunDeviceName)
	if err != nil {
		syscall.Close(socketFd)
		return nil, fmt.Errorf("BindToDevice failed: %s", err)
	}

	err = syscall.Connect(socketFd, sockAddr)
	if err != nil {
		syscall.Close(socketFd)
		return nil, fmt.Errorf("syscall.Connect failed: %s", err)
	}

	file := os.NewFile(uintptr(socketFd), "")
	conn, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return nil, fmt.Errorf("net.FileConn failed: %s", err)
	}

	return &testTCPClient{
		conn: conn,
	}, nil
}

func (client *testTCPClient) Read(p []byte) (n int, err error) {
	n, err = client.conn.Read(p)
	return
}

func (client *testTCPClient) Write(p []byte) (n int, err error) {
	n, err = client.conn.Write(p)
	return
}

func (client *testTCPClient) stop() {
	client.conn.Close()
}

type testLogger struct {
	packetMetrics chan common.LogFields
}

func newTestLogger(wantLastPacketMetrics bool) *testLogger {

	var packetMetrics chan common.LogFields
	if wantLastPacketMetrics {
		packetMetrics = make(chan common.LogFields, CONCURRENT_CLIENT_COUNT)
	}

	return &testLogger{
		packetMetrics: packetMetrics,
	}
}

func (logger *testLogger) WithContext() common.LogContext {
	return &testLoggerContext{context: common.GetParentContext()}
}

func (logger *testLogger) WithContextFields(fields common.LogFields) common.LogContext {
	return &testLoggerContext{
		context: common.GetParentContext(),
		fields:  fields,
	}
}

func (logger *testLogger) LogMetric(metric string, fields common.LogFields) {

	fmt.Printf("METRIC: %s: %+v\n", metric, fields)

	if metric == "packet_metrics" && logger.packetMetrics != nil {
		select {
		case logger.packetMetrics <- fields:
		default:
		}
	}
}

func (logger *testLogger) getLastPacketMetrics() common.LogFields {
	if logger.packetMetrics == nil {
		return nil
	}

	// Implicitly asserts that packet metrics will be emitted
	// within PACKET_METRICS_TIMEOUT; if not, the test will fail.

	select {
	case fields := <-logger.packetMetrics:
		return fields
	case <-time.After(PACKET_METRICS_TIMEOUT):
		return nil
	}
}

type testLoggerContext struct {
	context string
	fields  common.LogFields
}

func (context *testLoggerContext) log(priority, message string) {
	now := time.Now().UTC().Format(time.RFC3339)
	if len(context.fields) == 0 {
		fmt.Printf(
			"[%s] %s: %s: %s\n",
			now, priority, context.context, message)
	} else {
		fmt.Printf(
			"[%s] %s: %s: %s %+v\n",
			now, priority, context.context, message, context.fields)
	}
}

func (context *testLoggerContext) Debug(args ...interface{}) {
	context.log("DEBUG", fmt.Sprint(args...))
}

func (context *testLoggerContext) Info(args ...interface{}) {
	context.log("INFO", fmt.Sprint(args...))
}

func (context *testLoggerContext) Warning(args ...interface{}) {
	context.log("WARNING", fmt.Sprint(args...))
}

func (context *testLoggerContext) Error(args ...interface{}) {
	context.log("ERROR", fmt.Sprint(args...))
}
