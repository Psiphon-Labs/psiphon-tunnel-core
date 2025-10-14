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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// ErrorCallback receives error notifications with context.
type ErrorCallback func(err error, context string)

// MaxSocketPathLength returns the maximum length for a Unix Domain Socket
// path read directly from the syscall struct for the platform. 1 is then
// subtracted from the returned length to account for a null byte terminator.
func MaxSocketPathLength() int {
	var addr syscall.RawSockaddrUnix
	return int(unsafe.Sizeof(addr.Path) - 1)
}

// ResolveSocketPath determines the socket path to use.
func ResolveSocketPath(systemd *SystemdManager, fallbackPath string) string {
	if !systemd.IsSystemd() {
		return fallbackPath
	}

	runtimeDir := systemd.GetRuntimeDir()
	if runtimeDir == "" {
		return fallbackPath
	}

	return filepath.Join(runtimeDir, filepath.Base(fallbackPath))
}

// EnsureSocketDir creates the socket directory if it doesn't exist.
func EnsureSocketDir(socketPath string) error {
	dir := filepath.Dir(socketPath)

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("failed to create directory for socket path: %s: %w", socketPath, err)
	}

	return nil
}

// CleanupSocket removes the socket file if it exists.
func CleanupSocket(socketPath string) error {
	err := os.Remove(socketPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to cleanup socket: %s: %w", socketPath, err)
	}

	return nil
}

// LogEnvironment logs the current environment configuration.
func LogEnvironment(ctx context.Context, logger *slog.Logger, systemd *SystemdManager, socketPath string) {
	if systemd.IsSystemd() {
		logger.LogAttrs(ctx, slog.LevelInfo, "running under systemd",
			slog.String("socket_path", socketPath),
			slog.String("runtime_dir", systemd.GetRuntimeDir()),
			slog.String("state_dir", systemd.GetStateDir()),
			slog.Bool("socket_activation", systemd.GetSystemdListener() != nil),
			slog.Bool("ready_notification", systemd.notifyConn != nil),
		)
	} else {
		logger.LogAttrs(ctx, slog.LevelInfo, "running standalone", slog.String("socket_path", socketPath))
	}
}
