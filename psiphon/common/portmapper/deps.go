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

// This file provides minimal, self-contained replacements for the
// Tailscale-internal helper packages that the upstream net/portmapper code
// depended on. They are reimplemented here so that this fork has no
// tailscale.com imports. Each replacement copies only what the port mapper
// strictly requires:
//
//   - logf:        tailscale.com/types/logger.Logf / logger.Discard
//   - packetConn:  tailscale.com/types/nettype.PacketConn
//   - netaddr*:    tailscale.com/net/netaddr (IPv4, Unmap)
//   - treatAsLostUDP: tailscale.com/net/neterror.TreatAsLostUDP
//   - makSet:      tailscale.com/util/mak.Set
//   - registerBoolEnv: tailscale.com/envknob.RegisterBool
//   - ctxKey:      tailscale.com/util/ctxkey
//   - metric:      tailscale.com/util/clientmetric (per-process counters)
//
// The original Tailscale code is licensed as follows:
//
//	Copyright (c) Tailscale Inc & contributors
//	SPDX-License-Identifier: BSD-3-Clause

package portmapper

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// logf is the logging function type used throughout the port mapper. It is a
// drop-in for tailscale.com/types/logger.Logf.
type logf = func(format string, args ...any)

// discardLogf is a no-op logf, used when no logger is supplied. It replaces
// tailscale.com/types/logger.Discard.
func discardLogf(string, ...any) {}

// packetConn is the subset of *net.UDPConn used by the port mapper. It is a
// drop-in for tailscale.com/types/nettype.PacketConn.
type packetConn interface {
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	io.Closer
	LocalAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// netaddrIPv4 returns the netip.Addr for the IPv4 address a.b.c.d. It replaces
// tailscale.com/net/netaddr.IPv4.
func netaddrIPv4(a, b, c, d byte) netip.Addr {
	return netip.AddrFrom4([4]byte{a, b, c, d})
}

// netaddrUnmap returns ap with its address unmapped from any IPv4-in-IPv6
// representation. It replaces tailscale.com/net/netaddr.Unmap.
func netaddrUnmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// treatAsLostUDP reports whether err is the kind of write error that indicates
// a UDP packet was silently dropped (rather than a fatal socket error). It
// replaces tailscale.com/net/neterror.TreatAsLostUDP.
//
// On Linux, an OUTPUT firewall rule with -j DROP/REJECT surfaces as EPERM on
// the sendto syscall; we treat that as a lost packet. This is only done on
// Linux, matching the upstream behaviour.
func treatAsLostUDP(err error) bool {
	if err == nil {
		return false
	}
	if runtime.GOOS == "linux" {
		return errors.Is(err, syscall.EPERM)
	}
	return false
}

// makSet assigns m[k] = v, allocating the map through the pointer if it is nil.
// It replaces tailscale.com/util/mak.Set.
func makSet[K comparable, V any](m *map[K]V, k K, v V) {
	if *m == nil {
		*m = make(map[K]V)
	}
	(*m)[k] = v
}

// registerBoolEnv reads the named environment variable once and returns a func
// reporting its boolean value. It replaces tailscale.com/envknob.RegisterBool.
func registerBoolEnv(name string) func() bool {
	v, _ := strconv.ParseBool(os.Getenv(name))
	return func() bool { return v }
}

// ctxKey is a typed context key. It replaces tailscale.com/util/ctxkey.
type ctxKey[T any] struct {
	name string
	def  T
}

// newCtxKey returns a ctxKey with the given name and default value. It replaces
// ctxkey.New.
func newCtxKey[T any](name string, def T) *ctxKey[T] {
	return &ctxKey[T]{name: name, def: def}
}

// WithValue returns ctx with v stored under k.
func (k *ctxKey[T]) WithValue(ctx context.Context, v T) context.Context {
	return context.WithValue(ctx, k, v)
}

// Value returns the value stored under k in ctx, or k's default if unset.
func (k *ctxKey[T]) Value(ctx context.Context) T {
	if v, ok := ctx.Value(k).(T); ok {
		return v
	}
	return k.def
}

// metric is a minimal process-wide counter. It replaces the subset of
// tailscale.com/util/clientmetric used by the port mapper (NewCounter and Add).
// These counters are instrumentation only and are not part of any port mapping
// logic; responding port mapping types are reported per-Client (see Client).
type metric struct {
	n int64
}

// newCounter returns a new counter. The name is retained for documentation /
// parity with the upstream metric names but is otherwise unused.
func newCounter(name string) *metric {
	_ = name
	return &metric{}
}

// Add atomically adds v to the counter.
func (m *metric) Add(v int64) { atomic.AddInt64(&m.n, v) }

// Value atomically returns the counter's current value.
func (m *metric) Value() int64 { return atomic.LoadInt64(&m.n) }

// metricMap is a concurrency-safe lazily-populated map of counters keyed by an
// integer. It replaces the single tailscale.com/syncs.Map use in the port
// mapper (metricUPnPErrorsByCode).
type metricMap struct {
	mu sync.Mutex
	m  map[int]*metric
}

// loadOrInit returns the counter for code, creating it via newFn if absent.
func (mm *metricMap) loadOrInit(code int, newFn func() *metric) *metric {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	if mm.m == nil {
		mm.m = make(map[int]*metric)
	}
	if v, ok := mm.m[code]; ok {
		return v
	}
	v := newFn()
	mm.m[code] = v
	return v
}
