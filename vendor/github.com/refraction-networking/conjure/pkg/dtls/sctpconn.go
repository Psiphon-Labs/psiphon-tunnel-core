package dtls

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/sctp"
)

type msgStream interface {
	io.ReadWriteCloser
	BufferedAmount() uint64
	SetReadDeadline(deadline time.Time) error
	SetBufferedAmountLowThreshold(th uint64)
	OnBufferedAmountLow(f func())
}

// SCTPConn implements the net.Conn interface using sctp stream and DTLS conn
//
// SCTPConn buffers incoming SCTP messages, allowing the caller to use
// SCTPConn as a TCP-like bytes stream net.Conn, with reads smaller than
// individual message sizes.
type SCTPConn struct {
	stream         msgStream
	conn           net.Conn
	maxMessageSize uint64

	closeOnce sync.Once
	closed    chan struct{}

	write chan struct{}

	writeMutex sync.Mutex

	readMutex  sync.Mutex
	readBuffer []byte
	readOffset int
	readLength int
	readErr    error
}

// Limit for write flow control. This value should provide good performance
// while also strictly limiting sctp.Conn packet buffer sizes on
// limited-memory environments, such as iOS network extensions.
const (
	writeMaxBufferedAmount uint64 = 256 * 1024
)

func newSCTPConn(stream msgStream, conn net.Conn, maxMessageSize uint64) *SCTPConn {

	s := &SCTPConn{
		stream:         stream,
		conn:           conn,
		maxMessageSize: maxMessageSize,
		closed:         make(chan struct{}),
		write:          make(chan struct{}, 1),
		readBuffer:     make([]byte, maxMessageSize),
	}

	// Initialize write flow control, without which the underlying sctp.Client
	// may buffer an unbounded number of outbound packets, potentially
	// exceeding process memory limits, if the rate of write calls exceeds
	// the rate of sending packets. See:
	//
	// - https://github.com/pion/webrtc/tree/master/examples/data-channels-flow-control#when-do-we-need-it
	// - https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/commit/ea01c92cf1a9a13c1058b377ec547b43dfc164e1

	stream.SetBufferedAmountLowThreshold(writeMaxBufferedAmount / 2)
	stream.OnBufferedAmountLow(func() {
		select {
		case s.write <- struct{}{}:
		default:
		}
	})

	return s
}

func (s *SCTPConn) Close() error {

	// Unblock any write blocked due to flow control.

	s.closeOnce.Do(func() { close(s.closed) })

	err := s.stream.Close()
	if err != nil {
		return err
	}
	return s.conn.Close()
}

func (s *SCTPConn) Write(b []byte) (int, error) {

	writeLen := uint64(len(b))

	// Skip 0-byte writes, which are normally a no-op on a TCP-like net.Conn.
	// pion/sctp should skip 0-byte writes, and it appears that it doesn't
	// enqueue any packets, but it does increment a sequence number
	// (see links). Testing indicates that the underlying connection stalls
	// after a 0-byte write.
	//
	// - https://github.com/pion/sctp/blob/v1.8.8/stream.go#L254-L278
	// - https://github.com/pion/sctp/blob/v1.8.8/stream.go#L280-L336

	if writeLen == 0 {
		return 0, nil
	}

	// Fail if the write exceeds the maximum buffered amount (taking into
	// consideration that a write will proceed as long as at most
	// writeMaxBufferedAmount/2 bytes are already buffered). In this case,
	// SCTPConn will not behave the same as a TCP-like net.Conn, which has no
	// such limit, but this limit is not likely to be hit in practise.

	if writeLen > writeMaxBufferedAmount/2 {
		return 0, fmt.Errorf("write limit exceeded")
	}

	// Perform write flow control. If the current amount of buffered send
	// packets exceeds the limit, block until the amount drops or the conn is
	// closed.

	s.writeMutex.Lock()
	defer s.writeMutex.Unlock()
	if s.stream.BufferedAmount()+writeLen > writeMaxBufferedAmount {
		select {
		case <-s.closed:
			return 0, fmt.Errorf("closed")
		case <-s.write:
		}
	}

	return s.stream.Write(b)
}

func (s *SCTPConn) Read(b []byte) (int, error) {

	// As SCTP is a message stream and not a byte stream, sctp.Stream.Read
	// will fail with "short buffer" if SCTPConn.Read is invoked with a read
	// buffer smaller than the next read message. To accomodate callers
	// expecting TCP-like byte stream behavior, where each read can be for as
	// little as 1 byte, buffer each read message to support shorter reads.
	//
	// As per https://pkg.go.dev/io#Reader, bytes read are returned even when
	// the underlying read returns an error; the error value is stored and
	// returned with the read call that consumes the last byte of the message.

	s.readMutex.Lock()
	defer s.readMutex.Unlock()

	if s.readOffset == s.readLength {

		// Bypass the intermediate buffer if the caller provides a
		// sufficiently large read buffer.
		if uint64(len(b)) >= s.maxMessageSize {
			return s.stream.Read(b)
		}

		n, err := s.stream.Read(s.readBuffer)
		s.readOffset = 0
		s.readLength = n
		s.readErr = err
	}

	n := copy(b, s.readBuffer[s.readOffset:s.readLength])
	s.readOffset += n

	var err error
	if s.readOffset == s.readLength {
		err = s.readErr
	}

	return n, err
}

func (s *SCTPConn) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *SCTPConn) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func (s *SCTPConn) SetDeadline(t time.Time) error {
	return s.conn.SetDeadline(t)
}

func (s *SCTPConn) SetWriteDeadline(t time.Time) error {
	return s.conn.SetWriteDeadline(t)
}

func (s *SCTPConn) SetReadDeadline(t time.Time) error {
	return s.stream.SetReadDeadline(t)
}

func openSCTP(conn net.Conn, unordered bool) (net.Conn, error) {
	// Start SCTP
	sctpConf := sctp.Config{
		NetConn:       conn,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	}

	sctpClient, err := sctp.Client(sctpConf)

	if err != nil {
		return nil, fmt.Errorf("error creating sctp client: %v", err)
	}

	sctpStream, err := sctpClient.OpenStream(0, sctp.PayloadTypeWebRTCString)

	if err != nil {
		return nil, fmt.Errorf("error setting up stream: %v", err)
	}

	sctpStream.SetReliabilityParams(unordered, sctp.ReliabilityTypeReliable, 0)

	hbClient, err := heartbeatClient(sctpStream, &heartbeatConfig{Interval: 10 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("error opening heartbeat client: %v", err)
	}

	sctpConn := newSCTPConn(hbClient, conn, uint64(sctpClient.MaxMessageSize()))

	return sctpConn, nil
}

func acceptSCTP(conn net.Conn, unordered bool) (net.Conn, error) {

	// Start SCTP over DTLS connection
	sctpConfig := sctp.Config{
		NetConn:       conn,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	}

	sctpServer, err := sctp.Server(sctpConfig)
	if err != nil {
		return nil, err
	}

	sctpStream, err := sctpServer.AcceptStream()
	if err != nil {
		return nil, err
	}

	sctpStream.SetReliabilityParams(unordered, sctp.ReliabilityTypeReliable, 0)

	heartbeatConn, err := heartbeatServer(sctpStream, nil, int(sctpServer.MaxMessageSize()))
	if err != nil {
		return nil, fmt.Errorf("error starting heartbeat server: %v", err)
	}

	sctpConn := newSCTPConn(heartbeatConn, conn, uint64(sctpServer.MaxMessageSize()))

	return sctpConn, nil

}

func wrapSCTP(conn net.Conn, config *Config) (net.Conn, error) {
	if config.SCTP == ServerAccept {
		return acceptSCTP(conn, config.Unordered)
	}

	return openSCTP(conn, config.Unordered)
}
