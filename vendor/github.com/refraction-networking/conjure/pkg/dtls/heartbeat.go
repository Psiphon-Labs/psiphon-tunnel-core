package dtls

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var ErrInsufficientBuffer = errors.New("buffer too small to hold the received data")

const recvChBufSize = 64

type hbConn struct {
	stream msgStream

	closeOnce sync.Once
	closed    chan struct{}

	recvCh         chan errBytes
	waiting        uint32
	hb             []byte
	timeout        time.Duration
	maxMessageSize int
}

type errBytes struct {
	b   []byte
	err error
}

// heartbeatServer listens for heartbeat over conn with config
func heartbeatServer(stream msgStream, config *heartbeatConfig, maxMessageSize int) (*hbConn, error) {
	conf := validate(config)

	c := &hbConn{stream: stream,
		recvCh:         make(chan errBytes, recvChBufSize),
		timeout:        conf.Interval,
		hb:             conf.Heartbeat,
		closed:         make(chan struct{}),
		maxMessageSize: maxMessageSize,
	}

	atomic.StoreUint32(&c.waiting, 2)

	go c.recvLoop()
	go c.hbLoop()

	return c, nil
}

func (c *hbConn) hbLoop() {
	for {
		if atomic.LoadUint32(&c.waiting) == 0 {
			c.Close()
			return
		}

		atomic.StoreUint32(&c.waiting, 0)
		timer := time.NewTimer(c.timeout)
		select {
		case <-c.closed:
			timer.Stop()
			return
		case <-timer.C:
			continue
		}
	}

}

func (c *hbConn) recvLoop() {
	for {
		buffer := make([]byte, c.maxMessageSize)

		n, err := c.stream.Read(buffer)

		if bytes.Equal(c.hb, buffer[:n]) {
			atomic.AddUint32(&c.waiting, 1)
			continue
		}

		if err != nil {
			c.recvCh <- errBytes{nil, err}
			switch {
			case errors.Is(err, net.ErrClosed):
			case errors.Is(err, io.EOF):
				c.Close()
				return
			}
		}

		c.recvCh <- errBytes{buffer[:n], err}
	}

}

func (c *hbConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.stream.Close()
}

func (c *hbConn) Write(b []byte) (n int, err error) {
	return c.stream.Write(b)
}

func (c *hbConn) Read(b []byte) (int, error) {
	readBytes := <-c.recvCh
	if readBytes.err != nil {
		return 0, readBytes.err
	}

	if len(b) < len(readBytes.b) {
		return 0, ErrInsufficientBuffer
	}

	n := copy(b, readBytes.b)

	return n, nil
}

func (c *hbConn) BufferedAmount() uint64 {
	return c.stream.BufferedAmount()
}

func (c *hbConn) SetReadDeadline(deadline time.Time) error {
	return c.stream.SetReadDeadline(deadline)
}

func (c *hbConn) SetBufferedAmountLowThreshold(th uint64) {
	c.stream.SetBufferedAmountLowThreshold(th)
}

func (c *hbConn) OnBufferedAmountLow(f func()) {
	c.stream.OnBufferedAmountLow(f)
}

type hbClient struct {
	msgStream
	conf heartbeatConfig

	closeOnce sync.Once
	closed    chan struct{}
}

// heartbeatClient sends heartbeats over conn with config
func heartbeatClient(conn msgStream, config *heartbeatConfig) (msgStream, error) {
	conf := validate(config)
	client := &hbClient{msgStream: conn,
		conf:   conf,
		closed: make(chan struct{}),
	}
	go client.sendLoop()
	return client, nil
}

func (c *hbClient) sendLoop() {
	for {
		_, err := c.Write(c.conf.Heartbeat)
		if err != nil {
			return
		}

		timer := time.NewTimer(c.conf.Interval / 2)
		select {
		case <-c.closed:
			timer.Stop()
			return
		case <-timer.C:
			continue
		}
	}
}

func (c *hbClient) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.msgStream.Close()
}
