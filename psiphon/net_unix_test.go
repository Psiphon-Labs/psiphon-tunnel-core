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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// shortSocketTempDir returns a temporary directory with a short path. The
// default t.TempDir() can exceed the sockaddr_un sun_path length limit (104
// bytes on Darwin), which would cause bind to fail with "invalid argument".
func shortSocketTempDir(t *testing.T) string {
	dir, err := os.MkdirTemp("/tmp", "uds")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %s", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestMakeLocalProxyUnixListenerRoundTrip(t *testing.T) {

	dir := shortSocketTempDir(t)
	path := filepath.Join(dir, "test.sock")

	listener, err := makeLocalProxyUnixListener(path)
	if err != nil {
		t.Fatalf("makeLocalProxyUnixListener failed: %s", err)
	}
	defer listener.Close()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected socket file to exist: %s", err)
	}

	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := conn.Read(buf); err != nil {
			errCh <- err
			return
		}
		_, err = conn.Write(buf)
		errCh <- err
	}()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial failed: %s", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("Write failed: %s", err)
	}
	buf := make([]byte, 4)
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("Read failed: %s", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("expected echoed bytes 'ping', got %q", string(buf))
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server goroutine error: %s", err)
	}
}

func TestMakeLocalProxyUnixListenerStaleSocketCleanup(t *testing.T) {

	dir := shortSocketTempDir(t)
	path := filepath.Join(dir, "stale.sock")

	// Create a genuine stale socket node: listen to create the socket file,
	// then disable unlink-on-close so the socket file remains on disk after
	// Close with no active listener bound to it.
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("failed to create stale socket: %s", err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()

	if fileInfo, err := os.Lstat(path); err != nil {
		t.Fatalf("expected stale socket file to remain: %s", err)
	} else if fileInfo.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected leftover path to be a socket node")
	}

	listener, err := makeLocalProxyUnixListener(path)
	if err != nil {
		t.Fatalf("expected stale socket to be cleaned up, got: %s", err)
	}
	defer listener.Close()

	// Confirm the listener is usable.
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial to listener over reclaimed path failed: %s", err)
	}
	conn.Close()
}

func TestMakeLocalProxyUnixListenerRejectsNonSocketFile(t *testing.T) {

	dir := shortSocketTempDir(t)
	path := filepath.Join(dir, "regular.file")

	// A regular (non-socket) file must never be removed.
	if err := os.WriteFile(path, []byte("important"), 0600); err != nil {
		t.Fatalf("failed to create file: %s", err)
	}

	if _, err := makeLocalProxyUnixListener(path); err == nil {
		t.Fatalf("expected error for existing non-socket file")
	}

	// The file must still exist and be unchanged.
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected non-socket file to be preserved: %s", err)
	}
	if string(contents) != "important" {
		t.Fatalf("non-socket file was modified")
	}
}

func TestMakeLocalProxyUnixListenerDoesNotUnlinkActiveSocket(t *testing.T) {

	dir := shortSocketTempDir(t)
	path := filepath.Join(dir, "active.sock")

	// Bind an active listener on the path.
	active, err := makeLocalProxyUnixListener(path)
	if err != nil {
		t.Fatalf("first listener failed: %s", err)
	}
	defer active.Close()

	// A second attempt on the same active path must fail rather than unlink
	// the live socket and steal the path.
	if _, err := makeLocalProxyUnixListener(path); err == nil {
		t.Fatalf("expected error binding an active socket path")
	}

	// The original listener must still be usable.
	errCh := make(chan error, 1)
	go func() {
		conn, err := active.Accept()
		if err != nil {
			errCh <- err
			return
		}
		conn.Close()
		errCh <- nil
	}()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("original listener should still accept connections: %s", err)
	}
	conn.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("original listener Accept failed: %s", err)
	}
}

func TestMakeLocalProxyUnixListenerKeepsSocketOnNonRefusedDialError(t *testing.T) {

	// Connecting to a chmod-000 socket fails with EACCES rather than
	// ECONNREFUSED. Since EACCES does not prove the socket is stale, the path
	// must not be removed. Running as root bypasses the permission check, so
	// skip in that case.
	if os.Geteuid() == 0 {
		t.Skip("permission check is bypassed when running as root")
	}

	dir := shortSocketTempDir(t)
	path := filepath.Join(dir, "noperm.sock")

	// Create a stale socket node (no active listener) and remove all access
	// permissions so a test dial fails with EACCES.
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("failed to create socket: %s", err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	if err := os.Chmod(path, 0000); err != nil {
		t.Fatalf("chmod failed: %s", err)
	}

	if _, err := makeLocalProxyUnixListener(path); err == nil {
		t.Fatalf("expected error binding over a socket with a non-refused dial error")
	}

	// The socket node must still exist; it was not removed.
	if fileInfo, err := os.Lstat(path); err != nil {
		t.Fatalf("expected socket node to be preserved, stat err: %v", err)
	} else if fileInfo.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected preserved path to remain a socket node")
	}
}

func TestMakeLocalProxyUnixListenerCloseRemovesSocket(t *testing.T) {

	dir := shortSocketTempDir(t)
	path := filepath.Join(dir, "close.sock")

	listener, err := makeLocalProxyUnixListener(path)
	if err != nil {
		t.Fatalf("makeLocalProxyUnixListener failed: %s", err)
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("Close failed: %s", err)
	}

	// Go's net.UnixListener unlinks the socket file on Close by default.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected socket file to be removed on Close, stat err: %v", err)
	}

	// A second close must not panic.
	_ = listener.Close()
}

func TestMakeLocalProxyUnixListenerAbstractNamespace(t *testing.T) {

	if runtime.GOOS == "darwin" {
		t.Skip("abstract namespace sockets are not supported on Darwin")
	}

	path := "@psiphon-test-abstract"

	listener, err := makeLocalProxyUnixListener(path)
	if err != nil {
		t.Fatalf("makeLocalProxyUnixListener failed for abstract socket: %s", err)
	}
	defer listener.Close()

	// Abstract namespace sockets have no filesystem entry.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("abstract socket should not create a filesystem entry")
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial to abstract socket failed: %s", err)
	}
	conn.Close()
}
