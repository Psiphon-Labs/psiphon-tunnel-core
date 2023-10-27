package dtls

import (
	"bytes"
	"errors"
	"sync/atomic"
	"time"
)

var ErrInsufficientBuffer = errors.New("buffer too small to hold the received data")

const recvChBufSize = 64

type hbConn struct {
	stream msgStream

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
			c.stream.Close()
			return
		}

		atomic.StoreUint32(&c.waiting, 0)
		time.Sleep(c.timeout)
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
		}

		c.recvCh <- errBytes{buffer[:n], err}
	}

}

func (c *hbConn) Close() error {
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

// heartbeatClient sends heartbeats over conn with config
func heartbeatClient(conn msgStream, config *heartbeatConfig) error {
	conf := validate(config)
	go func() {
		for {
			_, err := conn.Write(conf.Heartbeat)
			if err != nil {
				return
			}

			time.Sleep(conf.Interval / 2)
		}

	}()
	return nil
}
