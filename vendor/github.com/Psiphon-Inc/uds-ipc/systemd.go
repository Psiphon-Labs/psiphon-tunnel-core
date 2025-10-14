/*
Copyright 2025 Psiphon Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package udsipc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
)

// SystemdManager handles systemd detection and integration.
type SystemdManager struct {
	listener   net.Listener
	notifyConn net.Conn
	runtimeDir string
	stateDir   string
	closeOnce  sync.Once
	isSystemd  bool
}

// NewSystemdManager creates a new systemd manager, setting up all systemd resources once.
func NewSystemdManager() (*SystemdManager, error) {
	manager := &SystemdManager{
		runtimeDir: os.Getenv("RUNTIME_DIRECTORY"),
		stateDir:   os.Getenv("STATE_DIRECTORY"),
	}

	listenFds := os.Getenv("LISTEN_FDS")
	notifySocket := os.Getenv("NOTIFY_SOCKET")

	manager.isSystemd = manager.runtimeDir != "" ||
		listenFds != "" ||
		notifySocket != ""

	if !manager.isSystemd {
		return manager, nil
	}

	// Set up socket activation listener if available.
	if listenFds != "" {
		listener, err := manager.setupSocketActivation(listenFds)
		if err != nil {
			return nil, fmt.Errorf("failed to setup socket activation: %w", err)
		}

		manager.listener = listener
	}

	// Set up notify connection if available.
	if notifySocket != "" {
		conn, err := manager.setupNotifyConnection(notifySocket)
		if err != nil {
			return nil, fmt.Errorf("failed to setup notify connection: %w", err)
		}

		manager.notifyConn = conn
	}

	return manager, nil
}

// setupSocketActivation configures the systemd-provided socket listener.
func (s *SystemdManager) setupSocketActivation(listenFdsStr string) (net.Listener, error) {
	// Validate LISTEN_PID matches current process.
	if listenPidStr := os.Getenv("LISTEN_PID"); listenPidStr != "" {
		listenPid, err := strconv.Atoi(listenPidStr)
		if err != nil {
			return nil, fmt.Errorf("invalid LISTEN_PID: %w", err)
		}
		if listenPid != os.Getpid() {
			return nil, fmt.Errorf("LISTEN_PID %d does not match current PID %d", listenPid, os.Getpid())
		}
	}

	listenFds, err := strconv.Atoi(listenFdsStr)
	if err != nil {
		return nil, fmt.Errorf("invalid LISTEN_FDS: %w", err)
	}

	if listenFds != 1 {
		return nil, fmt.Errorf("expected 1 socket, got %d", listenFds)
	}

	// nolint: mnd // Systemd passes file descriptor numbers starting at 3.
	file := os.NewFile(uintptr(3), "systemd-socket")
	if file == nil {
		return nil, errors.New("failed to create file from systemd fd")
	}

	listener, err := net.FileListener(file)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to create listener from systemd fd: %w", err)
	}

	// Close the file (listener now owns the fd).
	_ = file.Close()

	// Clean up environment variables (so potential child processes don't inherit them).
	_ = os.Unsetenv("LISTEN_FDS")
	_ = os.Unsetenv("LISTEN_PID")

	return listener, nil
}

// setupNotifyConnection configures the systemd notify connection.
func (s *SystemdManager) setupNotifyConnection(notifySocket string) (net.Conn, error) {
	conn, err := net.Dial("unixgram", notifySocket) // nolint: noctx
	if err != nil {
		return nil, fmt.Errorf("failed to connect to systemd notify socket: %w", err)
	}

	return conn, nil
}

// IsSystemd returns true if running under systemd.
func (s *SystemdManager) IsSystemd() bool {
	return s.isSystemd
}

// GetRuntimeDir returns the systemd runtime directory (empty if not).
func (s *SystemdManager) GetRuntimeDir() string {
	return s.runtimeDir
}

// GetStateDir returns the systemd state directory (empty if not).
func (s *SystemdManager) GetStateDir() string {
	return s.stateDir
}

// GetSystemdListener returns the pre-configured systemd listener (nil if not available).
func (s *SystemdManager) GetSystemdListener() net.Listener {
	return s.listener
}

// NotifyReady sends a ready notification to systemd (nil if not available).
func (s *SystemdManager) NotifyReady() error {
	if s.notifyConn == nil {
		return nil
	}

	_, err := s.notifyConn.Write([]byte("READY=1"))
	if err != nil {
		return fmt.Errorf("failed to send ready notification: %w", err)
	}

	return nil
}

// NotifyStopping sends a stopping notification to systemd (nil if not available).
func (s *SystemdManager) NotifyStopping() error {
	if s.notifyConn == nil {
		return nil
	}

	_, err := s.notifyConn.Write([]byte("STOPPING=1"))
	if err != nil {
		return fmt.Errorf("failed to send stopping notification: %w", err)
	}

	return nil
}

// NotifyStatus sends a status message to systemd (nil if not available).
func (s *SystemdManager) NotifyStatus(status string) error {
	if s.notifyConn == nil {
		return nil
	}

	message := fmt.Sprintf("STATUS=%s", status)
	_, err := s.notifyConn.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to send status notification: %w", err)
	}

	return nil
}

// Close cleans up systemd resources and notifies systemd of intended shutdown. Subsequent calls return nil.
func (s *SystemdManager) Close() error {
	var err error

	s.closeOnce.Do(func() {
		// If we aren't running under systemd, Close should just be a no-op with no error.
		if !s.isSystemd {
			return
		}

		if stopErr := s.NotifyStopping(); stopErr != nil {
			slog.LogAttrs(context.Background(), slog.LevelError, "failed to notify systemd stopping", slog.Any("error", stopErr))
		}

		if s.listener != nil {
			err = s.listener.Close()
		}

		if s.notifyConn != nil {
			err = errors.Join(err, s.notifyConn.Close())
		}
	})

	return err
}
