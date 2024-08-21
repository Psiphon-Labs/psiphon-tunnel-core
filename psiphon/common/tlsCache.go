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
	tls "github.com/Psiphon-Labs/psiphon-tls"
	utls "github.com/Psiphon-Labs/utls"
)

// TLSClientSessionCacheWrapper is a wrapper around tls.ClientSessionCache
// that provides a hard-coded key for the cache.
// It implements the TLSClientSessionCacheWrapper interface.
type TLSClientSessionCacheWrapper struct {
	tls.ClientSessionCache

	// sessionKey specifies the value of the hard-coded TLS session cache key.
	sessionKey string
}

// WrapClientSessionCache wraps a tls.ClientSessionCache with an alternative
// key, ignoring the SNI-based key that crypto/tls passes to Put/Get, which
// may be incompatible with SNI obfuscation transforms.
func WrapClientSessionCache(
	cache tls.ClientSessionCache,
	hardCodedSessionKey string,
) *TLSClientSessionCacheWrapper {

	return &TLSClientSessionCacheWrapper{
		ClientSessionCache: cache,
		sessionKey:         hardCodedSessionKey,
	}
}

func (c *TLSClientSessionCacheWrapper) Get(_ string) (session *tls.ClientSessionState, ok bool) {
	return c.ClientSessionCache.Get(c.sessionKey)
}

func (c *TLSClientSessionCacheWrapper) Put(_ string, cs *tls.ClientSessionState) {
	c.ClientSessionCache.Put(c.sessionKey, cs)
}

func (c *TLSClientSessionCacheWrapper) RemoveCacheEntry() {
	c.ClientSessionCache.Put(c.sessionKey, nil)
}

// UtlClientSessionCacheWrapper is a wrapper around utls.ClientSessionCache
// that provides a hard-coded key for the cache.
// It implements the TLSClientSessionCacheWrapper interface.
type UtlsClientSessionCacheWrapper struct {
	utls.ClientSessionCache

	// sessionKey specifies the value of the hard-coded TLS session cache key.
	sessionKey string
}

// WrapUtlsClientSessionCache wraps a utls.ClientSessionCache with an alternative
// key, ignoring the SNI-based key that crypto/tls passes to Put/Get, which
// may be incompatible with SNI obfuscation transforms.
func WrapUtlsClientSessionCache(
	cache utls.ClientSessionCache,
	hardCodedSessionKey string,
) *UtlsClientSessionCacheWrapper {

	return &UtlsClientSessionCacheWrapper{
		ClientSessionCache: cache,
		sessionKey:         hardCodedSessionKey,
	}
}

func (c *UtlsClientSessionCacheWrapper) Get(_ string) (session *utls.ClientSessionState, ok bool) {
	return c.ClientSessionCache.Get(c.sessionKey)
}

func (c *UtlsClientSessionCacheWrapper) Put(_ string, cs *utls.ClientSessionState) {
	c.ClientSessionCache.Put(c.sessionKey, cs)
}

func (c *UtlsClientSessionCacheWrapper) RemoveCacheEntry() {
	c.ClientSessionCache.Put(c.sessionKey, nil)
}
