/*
 * Copyright (c) 2016, Psiphon Inc.
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

package server

import (
	"bufio"
	"bytes"
	"math/rand"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/monotime"
)

const (
	DNS_SYSTEM_CONFIG_FILENAME      = "/etc/resolv.conf"
	DNS_SYSTEM_CONFIG_RELOAD_PERIOD = 5 * time.Second
	DNS_RESOLVER_PORT               = 53
)

// DNSResolver maintains fresh DNS resolver values, monitoring
// "/etc/resolv.conf" on platforms where it is available; and
// otherwise using a default value.
type DNSResolver struct {
	common.ReloadableFile
	isReloading    int32
	lastReloadTime atomic.Int64
	resolvers      []net.IP
}

// NewDNSResolver initializes a new DNSResolver, loading it with
// fresh resolver values. The load must succeed, so either
// "/etc/resolv.conf" must contain valid "nameserver" lines with
// a DNS server IP address, or a valid "defaultResolver" default
// value must be provided.
// On systems without "/etc/resolv.conf", "defaultResolver" is
// required.
//
// The resolver is considered stale and reloaded if last checked
// more than 5 seconds before the last Get(), which is similar to
// frequencies in other implementations:
//
//   - https://golang.org/src/net/dnsclient_unix.go,
//     resolverConfig.tryUpdate: 5 seconds
//
//   - https://github.com/ambrop72/badvpn/blob/master/udpgw/udpgw.c,
//     maybe_update_dns: 2 seconds
func NewDNSResolver(defaultResolver string) (*DNSResolver, error) {

	dns := &DNSResolver{}
	dns.lastReloadTime.Store(int64(monotime.Now()))

	dns.ReloadableFile = common.NewReloadableFile(
		DNS_SYSTEM_CONFIG_FILENAME,
		true,
		func(fileContent []byte, _ time.Time) error {

			resolvers, err := parseResolveConf(fileContent)
			if err != nil {
				// On error, state remains the same
				return errors.Trace(err)
			}

			dns.resolvers = resolvers

			log.WithTraceFields(
				LogFields{
					"resolvers": resolvers,
				}).Debug("loaded system DNS resolvers")

			return nil
		})

	_, err := dns.Reload()
	if err != nil {
		if defaultResolver == "" {
			return nil, errors.Trace(err)
		}

		log.WithTraceFields(
			LogFields{"err": err}).Info(
			"failed to load system DNS resolver; using default")

		resolver, err := parseResolver(defaultResolver)
		if err != nil {
			return nil, errors.Trace(err)
		}

		dns.resolvers = []net.IP{resolver}
	}

	return dns, nil
}

// Get returns one of the cached resolvers, selected at random,
// after first updating the cached values if they're stale. If
// reloading fails, the previous values are used.
//
// Randomly selecting any one of the configured resolvers is
// expected to be more resiliant to failure; e.g., if one of
// the resolvers becomes unavailable.
func (dns *DNSResolver) Get() net.IP {

	dns.reloadWhenStale()

	dns.ReloadableFile.RLock()
	defer dns.ReloadableFile.RUnlock()

	return dns.resolvers[rand.Intn(len(dns.resolvers))]
}

func (dns *DNSResolver) reloadWhenStale() {

	// Every UDP DNS port forward frequently calls Get(), so this code
	// is intended to minimize blocking. Most callers will hit just the
	// atomic.LoadInt64 reload time check and the RLock (an atomic.AddInt32
	// when no write lock is pending). An atomic.CompareAndSwapInt32 is
	// used to ensure only one goroutine enters Reload() and blocks on
	// its write lock. Finally, since since ReloadableFile.Reload
	// checks whether the underlying file has changed _before_ acquiring a
	// write lock, we only incur write lock blocking when "/etc/resolv.conf"
	// has actually changed.

	lastReloadTime := monotime.Time(dns.lastReloadTime.Load())
	stale := monotime.Now().After(lastReloadTime.Add(DNS_SYSTEM_CONFIG_RELOAD_PERIOD))

	if stale {

		isReloader := atomic.CompareAndSwapInt32(&dns.isReloading, 0, 1)

		if isReloader {

			// Unconditionally set last reload time. Even on failure only
			// want to retry after another DNS_SYSTEM_CONFIG_RELOAD_PERIOD.
			dns.lastReloadTime.Store(int64(monotime.Now()))

			_, err := dns.Reload()
			if err != nil {
				log.WithTraceFields(
					LogFields{"err": err}).Info(
					"failed to reload system DNS resolver")
			}

			atomic.StoreInt32(&dns.isReloading, 0)
		}
	}
}

// GetAll returns a list of all DNS resolver addresses. Cached values are
// updated if they're stale. If reloading fails, the previous values are
// used.
func (dns *DNSResolver) GetAll() []net.IP {
	return dns.getAll(true, true)
}

// GetAllIPv4 returns a list of all IPv4 DNS resolver addresses.
// Cached values are updated if they're stale. If reloading fails,
// the previous values are used.
func (dns *DNSResolver) GetAllIPv4() []net.IP {
	return dns.getAll(true, false)
}

// GetAllIPv6 returns a list of all IPv6 DNS resolver addresses.
// Cached values are updated if they're stale. If reloading fails,
// the previous values are used.
func (dns *DNSResolver) GetAllIPv6() []net.IP {
	return dns.getAll(false, true)
}

func (dns *DNSResolver) getAll(wantIPv4, wantIPv6 bool) []net.IP {

	dns.reloadWhenStale()

	dns.ReloadableFile.RLock()
	defer dns.ReloadableFile.RUnlock()

	resolvers := make([]net.IP, 0)
	for _, resolver := range dns.resolvers {
		if resolver.To4() != nil {
			if wantIPv4 {
				resolvers = append(resolvers, resolver)
			}
		} else {
			if wantIPv6 {
				resolvers = append(resolvers, resolver)
			}
		}
	}
	return resolvers
}

func parseResolveConf(fileContent []byte) ([]net.IP, error) {

	scanner := bufio.NewScanner(bytes.NewReader(fileContent))

	var resolvers []net.IP

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "nameserver" {
			resolver, err := parseResolver(fields[1])
			if err == nil {
				resolvers = append(resolvers, resolver)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.Trace(err)
	}

	if len(resolvers) == 0 {
		return nil, errors.TraceNew("no nameservers found")
	}

	return resolvers, nil
}

func parseResolver(resolver string) (net.IP, error) {

	ipAddress := net.ParseIP(resolver)
	if ipAddress == nil {
		return nil, errors.TraceNew("invalid IP address")
	}

	return ipAddress, nil
}
