//go:build darwin || android || linux
// +build darwin android linux

/*
 * Copyright (c) 2026, Psiphon Inc.
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

package psiphon

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// directTunneler is a Tunneler that dials destinations directly, simulating a
// tunnel for local proxy integration testing.
type directTunneler struct{}

func (t *directTunneler) Dial(remoteAddr string, downstreamConn net.Conn) (net.Conn, error) {
	return net.Dial("tcp", remoteAddr)
}

func (t *directTunneler) DirectDial(remoteAddr string) (net.Conn, error) {
	return net.Dial("tcp", remoteAddr)
}

func (t *directTunneler) SignalComponentFailure() {}

// startEchoOrigin starts a TCP server that echoes a fixed greeting and then
// echoes back anything it receives. It returns the listen address.
func startEchoOrigin(t *testing.T) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin Listen failed: %s", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	return listener.Addr().String()
}

func shortUnixPath(t *testing.T, name string) string {
	dir, err := os.MkdirTemp("/tmp", "uds")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %s", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

// newCommittedUnixProxyConfig returns a committed Config that runs the local
// proxies on Unix domain sockets. Commit initializes parameters, which the
// HTTP proxy requires.
func newCommittedUnixProxyConfig(t *testing.T, socksPath, httpPath string) *Config {
	dataRootDirectory, err := os.MkdirTemp("/tmp", "uds-cfg")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %s", err)
	}
	t.Cleanup(func() { os.RemoveAll(dataRootDirectory) })

	config := &Config{
		DataRootDirectory:       dataRootDirectory,
		PropagationChannelId:    "ABCDEFGH",
		SponsorId:               "12345678",
		ClientVersion:           "1",
		UseUnixDomainSockets:    true,
		LocalSocksProxyUnixPath: socksPath,
		LocalHttpProxyUnixPath:  httpPath,
	}
	if socksPath == "" {
		config.DisableLocalSocksProxy = true
	}
	if httpPath == "" {
		config.DisableLocalHTTPProxy = true
	}

	if err := config.Commit(false); err != nil {
		t.Fatalf("Commit failed: %s", err)
	}
	return config
}

func TestSocksProxyOverUnixSocket(t *testing.T) {

	originAddr := startEchoOrigin(t)
	socketPath := shortUnixPath(t, "socks.sock")

	config := newCommittedUnixProxyConfig(t, socketPath, "")

	proxyServer, err := NewSocksProxy(config, &directTunneler{}, "")
	if err != nil {
		t.Fatalf("NewSocksProxy failed: %s", err)
	}
	defer proxyServer.Close()

	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("expected SOCKS socket file to exist: %s", err)
	}

	// Dial the SOCKS server over the Unix domain socket.
	dialer, err := proxy.SOCKS5("unix", socketPath, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("proxy.SOCKS5 failed: %s", err)
	}

	conn, err := dialer.Dial("tcp", originAddr)
	if err != nil {
		t.Fatalf("SOCKS dial through Unix socket failed: %s", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("hello-socks")); err != nil {
		t.Fatalf("write failed: %s", err)
	}
	buf := make([]byte, len("hello-socks"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read failed: %s", err)
	}
	if string(buf) != "hello-socks" {
		t.Fatalf("expected echoed 'hello-socks', got %q", string(buf))
	}
}

func TestHttpProxyOverUnixSocket(t *testing.T) {

	// Start an HTTP origin server.
	originListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin Listen failed: %s", err)
	}
	defer originListener.Close()

	originServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "hello-http")
		}),
	}
	go originServer.Serve(originListener)
	defer originServer.Close()

	originURL := "http://" + originListener.Addr().String() + "/"

	socketPath := shortUnixPath(t, "http.sock")

	config := newCommittedUnixProxyConfig(t, "", socketPath)

	proxyServer, err := NewHttpProxy(config, &directTunneler{}, "")
	if err != nil {
		t.Fatalf("NewHttpProxy failed: %s", err)
	}
	defer proxyServer.Close()

	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("expected HTTP socket file to exist: %s", err)
	}

	// Connect to the HTTP proxy over the Unix domain socket and issue a
	// proxy-form request: the request line carries the absolute origin URL,
	// which is how an HTTP proxy client signals a proxied request. This
	// exercises the proxy's httpProxyHandler path.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Dial to HTTP proxy over Unix socket failed: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req, err := http.NewRequest("GET", originURL, nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %s", err)
	}
	// WriteProxy writes the request in proxy form (absolute URI in the
	// request line).
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("WriteProxy failed: %s", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("ReadResponse failed: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %s", err)
	}
	if string(body) != "hello-http" {
		t.Fatalf("expected 'hello-http', got %q", string(body))
	}
}

func TestHttpProxyConnectOverUnixSocket(t *testing.T) {

	// CONNECT is how HTTPS clients tunnel arbitrary TCP through an HTTP proxy.
	// Use a TCP echo origin as the CONNECT target.
	originAddr := startEchoOrigin(t)

	socketPath := shortUnixPath(t, "http.sock")
	config := newCommittedUnixProxyConfig(t, "", socketPath)

	proxyServer, err := NewHttpProxy(config, &directTunneler{}, "")
	if err != nil {
		t.Fatalf("NewHttpProxy failed: %s", err)
	}
	defer proxyServer.Close()

	// Connect to the HTTP proxy over the Unix domain socket and issue a
	// CONNECT request to establish a raw tunnel to the origin.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Dial to HTTP proxy over Unix socket failed: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	connectReq, err := http.NewRequest("CONNECT", "//"+originAddr, nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %s", err)
	}
	connectReq.Host = originAddr
	if err := connectReq.Write(conn); err != nil {
		t.Fatalf("writing CONNECT failed: %s", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		t.Fatalf("reading CONNECT response failed: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 Connection Established, got %d", resp.StatusCode)
	}

	// The tunnel is now raw bytes to the echo origin.
	if _, err := conn.Write([]byte("tunnel-bytes")); err != nil {
		t.Fatalf("write through CONNECT tunnel failed: %s", err)
	}
	buf := make([]byte, len("tunnel-bytes"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read through CONNECT tunnel failed: %s", err)
	}
	if string(buf) != "tunnel-bytes" {
		t.Fatalf("expected echoed 'tunnel-bytes', got %q", string(buf))
	}
}

func TestUnixSocketListeningNotices(t *testing.T) {

	socksPath := shortUnixPath(t, "socks.sock")
	httpPath := shortUnixPath(t, "http.sock")

	gotSocksPath := make(chan string, 1)
	gotHttpPath := make(chan string, 1)

	err := SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
		noticeType, payload, err := GetNotice(notice)
		if err != nil {
			return
		}
		switch noticeType {
		case "ListeningSocksProxyUnixPath":
			select {
			case gotSocksPath <- payload["path"].(string):
			default:
			}
		case "ListeningHttpProxyUnixPath":
			select {
			case gotHttpPath <- payload["path"].(string):
			default:
			}
		}
	}))
	if err != nil {
		t.Fatalf("SetNoticeWriter failed: %s", err)
	}
	defer ResetNoticeWriter()

	socksConfig := newCommittedUnixProxyConfig(t, socksPath, "")
	socksProxy, err := NewSocksProxy(socksConfig, &directTunneler{}, "")
	if err != nil {
		t.Fatalf("NewSocksProxy failed: %s", err)
	}
	defer socksProxy.Close()

	httpConfig := newCommittedUnixProxyConfig(t, "", httpPath)
	httpProxy, err := NewHttpProxy(httpConfig, &directTunneler{}, "")
	if err != nil {
		t.Fatalf("NewHttpProxy failed: %s", err)
	}
	defer httpProxy.Close()

	select {
	case path := <-gotSocksPath:
		if path != socksPath {
			t.Fatalf("ListeningSocksProxyUnixPath = %q, want %q", path, socksPath)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("did not receive ListeningSocksProxyUnixPath notice")
	}

	select {
	case path := <-gotHttpPath:
		if path != httpPath {
			t.Fatalf("ListeningHttpProxyUnixPath = %q, want %q", path, httpPath)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("did not receive ListeningHttpProxyUnixPath notice")
	}
}
