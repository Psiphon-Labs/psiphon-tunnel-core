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

const TLS_NULL_SESSION_KEY = ""

// TLSClientSessionCacheWrapper is a wrapper around tls.ClientSessionCache
// that provides a hard-coded key for the cache.
type TLSClientSessionCacheWrapper struct {
	tls.ClientSessionCache

	// sessionKey specifies the value of the hard-coded TLS session cache key.
	sessionKey string
}

// WrapUtlsClientSessionCache wraps a tls.ClientSessionCache with an alternative
// hard-coded session key, ignoring the SNI-based key that crypto/tls passes to Put/Get,
// which may be incompatible with the SNI obfuscation transforms.
// If the sessionKey is empty (TLS_NULL_SESSION_KEY), SetSessionKey has to be called
// before using the cache.
func WrapClientSessionCache(
	cache tls.ClientSessionCache,
	hardCodedSessionKey string,
) *TLSClientSessionCacheWrapper {
	return &TLSClientSessionCacheWrapper{
		ClientSessionCache: cache,
		sessionKey:         hardCodedSessionKey,
	}
}

// Get retrieves the session from the cache using the hard-coded session key.
func (c *TLSClientSessionCacheWrapper) Get(_ string) (session *tls.ClientSessionState, ok bool) {
	if c.sessionKey == "" {
		return nil, false
	}
	return c.ClientSessionCache.Get(c.sessionKey)
}

// Put stores the session in the cache using the hard-coded session key.
func (c *TLSClientSessionCacheWrapper) Put(_ string, cs *tls.ClientSessionState) {
	if c.sessionKey == "" {
		return
	}
	cs.ResumptionState()
	c.ClientSessionCache.Put(c.sessionKey, cs)
}

// RemoveCacheEntry removes the cache entry for the hard-coded session key.
func (c *TLSClientSessionCacheWrapper) RemoveCacheEntry() {
	if c.sessionKey == "" {
		return
	}
	c.ClientSessionCache.Put(c.sessionKey, nil)
}

// SetSessionKey sets the hard-coded session key if not already set.
func (c *TLSClientSessionCacheWrapper) SetSessionKey(key string) {
	if c.sessionKey != TLS_NULL_SESSION_KEY {
		return
	}
	c.sessionKey = key
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
// hard-coded session key, ignoring the SNI-based key that crypto/tls passes to Put/Get,
// which may be incompatible with the SNI obfuscation transforms.
// If the sessionKey is empty (TLS_NULL_SESSION_KEY), SetSessionKey has to be called
// before using the cache.
func WrapUtlsClientSessionCache(
	cache utls.ClientSessionCache,
	hardCodedSessionKey string,
) *UtlsClientSessionCacheWrapper {
	return &UtlsClientSessionCacheWrapper{
		ClientSessionCache: cache,
		sessionKey:         hardCodedSessionKey,
	}
}

// Get retrieves the session from the cache using the hard-coded session key.
func (c *UtlsClientSessionCacheWrapper) Get(_ string) (session *utls.ClientSessionState, ok bool) {
	if c.sessionKey == "" {
		return nil, false
	}
	return c.ClientSessionCache.Get(c.sessionKey)
}

// Put stores the session in the cache using the hard-coded session key.
func (c *UtlsClientSessionCacheWrapper) Put(_ string, cs *utls.ClientSessionState) {
	if c.sessionKey == "" {
		return
	}
	c.ClientSessionCache.Put(c.sessionKey, cs)
}

// RemoveCacheEntry removes the cache entry for the hard-coded session key.
func (c *UtlsClientSessionCacheWrapper) RemoveCacheEntry() {
	if c.sessionKey != "" {
		c.ClientSessionCache.Put(c.sessionKey, nil)
	}
}

// SetSessionKey sets the hard-coded session key if not already set.
// If the session key is already set, it does nothing.
func (c *UtlsClientSessionCacheWrapper) SetSessionKey(key string) {
	if c.sessionKey != TLS_NULL_SESSION_KEY {
		return
	}
	c.sessionKey = key
}
