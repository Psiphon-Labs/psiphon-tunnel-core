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
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Inc/goarista/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

const (
	DNS_SYSTEM_CONFIG_FILENAME      = "/etc/resolv.conf"
	DNS_SYSTEM_CONFIG_RELOAD_PERIOD = 5 * time.Second
	DNS_RESOLVER_PORT               = 53
)

// DNSResolver maintains a fresh DNS resolver value, monitoring
// "/etc/resolv.conf" on platforms where it is available; and
// otherwise using a default value.
type DNSResolver struct {
	// Note: 64-bit ints used with atomic operations are at placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	lastReloadTime int64
	common.ReloadableFile
	isReloading int32
	resolver    net.IP
}

// NewDNSResolver initializes a new DNSResolver, loading it with
// a fresh resolver value. The load must succeed, so either
// "/etc/resolv.conf" must contain a valid "nameserver" line with
// a DNS server IP address, or a valid "defaultResolver" default
// value must be provided.
// On systems without "/etc/resolv.conf", "defaultResolver" is
// required.
//
// The resolver is considered stale and reloaded if last checked
// more than 5 seconds before the last Get(), which is similar to
// frequencies in other implementations:
//
// - https://golang.org/src/net/dnsclient_unix.go,
//   resolverConfig.tryUpdate: 5 seconds
//
// - https://github.com/ambrop72/badvpn/blob/master/udpgw/udpgw.c,
//   maybe_update_dns: 2 seconds
//
func NewDNSResolver(defaultResolver string) (*DNSResolver, error) {

	dns := &DNSResolver{
		lastReloadTime: int64(monotime.Now()),
	}

	dns.ReloadableFile = common.NewReloadableFile(
		DNS_SYSTEM_CONFIG_FILENAME,
		func(filename string) error {

			resolver, err := parseResolveConf(filename)
			if err != nil {
				// On error, state remains the same
				return common.ContextError(err)
			}

			dns.resolver = resolver

			log.WithContextFields(
				LogFields{
					"resolver": resolver.String(),
				}).Debug("loaded system DNS resolver")

			return nil
		})

	_, err := dns.Reload()
	if err != nil {
		if defaultResolver == "" {
			return nil, common.ContextError(err)
		}

		log.WithContextFields(
			LogFields{"err": err}).Info(
			"failed to load system DNS resolver; using default")

		resolver, err := parseResolver(defaultResolver)
		if err != nil {
			return nil, common.ContextError(err)
		}

		dns.resolver = resolver
	}

	return dns, nil
}

// Get returns the cached resolver, first updating the cached
// value if it's stale. If reloading fails, the previous value
// is used.
func (dns *DNSResolver) Get() net.IP {

	// Every UDP DNS port forward frequently calls Get(), so this code
	// is intended to minimize blocking. Most callers will hit just the
	// atomic.LoadInt64 reload time check and the RLock (an atomic.AddInt32
	// when no write lock is pending). An atomic.CompareAndSwapInt32 is
	// used to ensure only one goroutine enters Reload() and blocks on
	// its write lock. Finally, since since ReloadableFile.Reload
	// checks whether the underlying file has changed _before_ aquiring a
	// write lock, we only incur write lock blocking when "/etc/resolv.conf"
	// has actually changed.

	lastReloadTime := monotime.Time(atomic.LoadInt64(&dns.lastReloadTime))
	stale := monotime.Now().After(lastReloadTime.Add(DNS_SYSTEM_CONFIG_RELOAD_PERIOD))

	if stale {

		isReloader := atomic.CompareAndSwapInt32(&dns.isReloading, 0, 1)

		if isReloader {

			// Unconditionally set last reload time. Even on failure only
			// want to retry after another DNS_SYSTEM_CONFIG_RELOAD_PERIOD.
			atomic.StoreInt64(&dns.lastReloadTime, time.Now().Unix())

			_, err := dns.Reload()
			if err != nil {
				log.WithContextFields(
					LogFields{"err": err}).Info(
					"failed to reload system DNS resolver")
			}

			atomic.StoreInt32(&dns.isReloading, 0)
		}
	}

	dns.ReloadableFile.RLock()
	defer dns.ReloadableFile.RUnlock()

	return dns.resolver
}

func parseResolveConf(filename string) (net.IP, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, common.ContextError(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "nameserver" {
			// TODO: parseResolverAddress will fail when the nameserver
			// is not an IP address. It may be a domain name. To support
			// this case, should proceed to the next "nameserver" line.
			return parseResolver(fields[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, common.ContextError(err)
	}
	return nil, common.ContextError(errors.New("nameserver not found"))
}

func parseResolver(resolver string) (net.IP, error) {

	ipAddress := net.ParseIP(resolver)
	if ipAddress == nil {
		return nil, common.ContextError(errors.New("invalid IP address"))
	}

	return ipAddress, nil
}
