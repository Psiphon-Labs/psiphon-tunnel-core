package marionette

import (
	"io"
	"net"
	"sync"

	"github.com/armon/go-socks5"
	"go.uber.org/zap"
)

// ServerProxy represents a proxy between a marionette listener and another server.
type ServerProxy struct {
	ln *Listener
	wg sync.WaitGroup

	// Host and port to proxy requests to.
	// Ignored if a socks5 server is enabled.
	Addr string

	// Server used for proxying requests.
	Socks5Server *socks5.Server
}

// NewServerProxy returns a new instance of ServerProxy.
func NewServerProxy(ln *Listener) *ServerProxy {
	return &ServerProxy{ln: ln}
}

func (p *ServerProxy) Open() error {
	p.wg.Add(1)
	go func() { defer p.wg.Done(); p.run() }()

	return nil
}

func (p *ServerProxy) Close() error {
	return nil
}

func (p *ServerProxy) run() {
	Logger.Debug("server proxy: listening")
	defer Logger.Debug("server proxy: closed")

	for {
		conn, err := p.ln.Accept()
		if err != nil {
			Logger.Debug("server proxy: listener error", zap.Error(err))
			return
		}

		p.wg.Add(1)
		go func() { defer p.wg.Done(); p.handleConn(conn) }()
	}
}

func (p *ServerProxy) handleConn(conn net.Conn) {
	defer conn.Close()

	Logger.Debug("server proxy: connection open")
	defer Logger.Debug("server proxy: connection closed")

	// If the proxy address is "socks5" then hand off to socks5 server.
	if p.Socks5Server != nil {
		if err := p.Socks5Server.ServeConn(conn); err != nil {
			Logger.Debug("server proxy: socks5 error", zap.Error(err))
		}
		return
	}

	// Connect to remote server.
	proxyConn, err := net.Dial("tcp", p.Addr)
	if err != nil {
		Logger.Debug("server proxy: cannot connect to remote server", zap.String("address", p.Addr))
		return
	}
	defer proxyConn.Close()

	// Copy between connection and proxy until an error occurs.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(proxyConn, conn)
		proxyConn.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, proxyConn)
	}()
	wg.Wait()
}
