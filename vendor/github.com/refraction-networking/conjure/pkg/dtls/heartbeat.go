package dtls

import (
	"bytes"
	"net"
	"sync/atomic"
	"time"
)

var maxMessageSize = 65535

type hbConn struct {
	conn    net.Conn
	recvCh  chan errBytes
	waiting uint32
	hb      []byte
	timeout time.Duration
}

type errBytes struct {
	b   []byte
	err error
}

// heartbeatServer listens for heartbeat over conn with config
func heartbeatServer(conn net.Conn, config *heartbeatConfig) (net.Conn, error) {
	conf := validate(config)

	c := &hbConn{conn: conn,
		recvCh:  make(chan errBytes),
		timeout: conf.Interval,
		hb:      conf.Heartbeat,
	}

	atomic.StoreUint32(&c.waiting, 2)

	go c.recvLoop()
	go c.hbLoop()

	return c, nil
}

func (c *hbConn) hbLoop() {
	for {
		if atomic.LoadUint32(&c.waiting) == 0 {
			c.conn.Close()
			return
		}

		atomic.StoreUint32(&c.waiting, 0)
		time.Sleep(c.timeout)
	}

}

func (c *hbConn) recvLoop() {
	for {
		// create a buffer to hold your data
		buffer := make([]byte, maxMessageSize)

		n, err := c.conn.Read(buffer)

		if bytes.Equal(c.hb, buffer[:n]) {
			atomic.AddUint32(&c.waiting, 1)
			continue
		}

		c.recvCh <- errBytes{buffer[:n], err}
	}

}

func (c *hbConn) Close() error {
	return c.conn.Close()
}

func (c *hbConn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

func (c *hbConn) Read(b []byte) (n int, err error) {
	readBytes := <-c.recvCh
	copy(b, readBytes.b)

	return len(readBytes.b), readBytes.err
}

func (c *hbConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *hbConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *hbConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *hbConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *hbConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// heartbeatClient sends heartbeats over conn with config
func heartbeatClient(conn net.Conn, config *heartbeatConfig) error {
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
