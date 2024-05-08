/*
 * Copyright (c) 2024, Psiphon Inc.
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

package common

import (
	"fmt"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	utls "github.com/refraction-networking/utls"
)

// TlsClientSessionCacheWrapper is a wrapper around tls.ClientSessionCache
// that provides a hard-coded key for the cache.
// It implements the TLSClientSessionCacheWrapper interface.
type TlsClientSessionCacheWrapper struct {
	tls.ClientSessionCache

	// sessinoKey specifies the value of the hard-coded TLS session cache key.
	sessionKey string
}

// WrapClientSessionCache wraps a tls.ClientSessionCache with a hard-coded key
// derived from the ipAddress and dialPortNumber.
func WrapClientSessionCache(
	cache tls.ClientSessionCache,
	ipAddress string,
	dialPortNumber int) *TlsClientSessionCacheWrapper {

	return &TlsClientSessionCacheWrapper{
		ClientSessionCache: cache,
		sessionKey:         sessionKey(ipAddress, dialPortNumber),
	}
}

func (c *TlsClientSessionCacheWrapper) Get(_ string) (session *tls.ClientSessionState, ok bool) {
	return c.ClientSessionCache.Get(c.sessionKey)
}

func (c *TlsClientSessionCacheWrapper) Put(_ string, cs *tls.ClientSessionState) {
	c.ClientSessionCache.Put(c.sessionKey, cs)
}

func (c *TlsClientSessionCacheWrapper) IsSessionResumptionAvailable() bool {
	// Ignore the ok return value, as the session may still be till if ok is true.
	session, _ := c.Get(c.sessionKey)
	return session != nil
}

func (c *TlsClientSessionCacheWrapper) RemoveCacheEntry() {
	c.ClientSessionCache.Put(c.sessionKey, nil)
}

// UtlClientSessionCacheWrapper is a wrapper around utls.ClientSessionCache
// that provides a hard-coded key for the cache.
// It implements the TLSClientSessionCacheWrapper interface.
type UtlsClientSessionCacheWrapper struct {
	utls.ClientSessionCache

	// sessinoKey specifies the value of the hard-coded TLS session cache key.
	sessionKey string
}

// WrapUtlsClientSessionCache wraps a utls.ClientSessionCache with a hard-coded key
// derived from the ipAddress and dialPortNumber.
func WrapUtlsClientSessionCache(
	cache utls.ClientSessionCache,
	ipAddress string,
	dialPortNumber int) *UtlsClientSessionCacheWrapper {

	return &UtlsClientSessionCacheWrapper{
		ClientSessionCache: cache,
		sessionKey:         sessionKey(ipAddress, dialPortNumber),
	}
}

func (c *UtlsClientSessionCacheWrapper) Get(_ string) (session *utls.ClientSessionState, ok bool) {
	return c.ClientSessionCache.Get(c.sessionKey)
}

func (c *UtlsClientSessionCacheWrapper) Put(_ string, cs *utls.ClientSessionState) {
	c.ClientSessionCache.Put(c.sessionKey, cs)
}

func (c *UtlsClientSessionCacheWrapper) IsSessionResumptionAvailable() bool {
	// Ignore the ok return value, as the session may still be till if ok is true.
	session, _ := c.Get(c.sessionKey)
	return session != nil
}

func (c *UtlsClientSessionCacheWrapper) RemoveCacheEntry() {
	c.ClientSessionCache.Put(c.sessionKey, nil)
}

func sessionKey(ipAddress string, dialPortNumber int) string {
	return fmt.Sprintf("%s:%d", ipAddress, dialPortNumber)
}
