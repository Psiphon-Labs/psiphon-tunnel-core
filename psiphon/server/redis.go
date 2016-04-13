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
	"encoding/json"

	"github.com/Psiphon-Inc/redigo/redis"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// UpdateRedisForLegacyPsiWeb sets the Psiphon session and discovery records for
// a new SSH connection following the conventions of the legacy psi_web component.
// This facility is used so psi_web can use the GeoIP values the SSH server has
// resolved for the user connection.
// The redis database indexes, expiry values, and record schemas all match the
// legacy psi_web configuration.
func UpdateRedisForLegacyPsiWeb(psiphonSessionID string, geoIPData GeoIPData) error {

	redisSessionDBIndex := 0

	//  Discard sessions older than 60 minutes
	sessionExpireSeconds := 60 * 60

	sessionRecord, err := json.Marshal(
		struct {
			country string `json:"region"`
			city    string `json:"city"`
			ISP     string `json:"isp"`
		}{geoIPData.Country, geoIPData.City, geoIPData.ISP})
	if err != nil {
		return psiphon.ContextError(err)
	}

	redisDiscoveryDBIndex := 1

	// Discard discovery records older than 5 minutes
	discoveryExpireSeconds := 60 * 5

	// TODO: implement psi_ops_discovery.calculate_ip_address_strategy_value
	discoveryValue := 0

	discoveryRecord, err := json.Marshal(
		struct {
			value int `json:"client_ip_address_strategy_value"`
		}{discoveryValue})
	if err != nil {
		return psiphon.ContextError(err)
	}

	conn := redisPool.Get()

	// Note: using SET with NX (set if not exists) so as to not clobber
	// any existing records set by an upstream connection server (i.e.,
	// meek server). We allow expiry deadline extension unconditionally.

	conn.Send("MULTI")
	conn.Send("SELECT", redisSessionDBIndex)
	conn.Send("SET", psiphonSessionID, string(sessionRecord), "NX", "EX", sessionExpireSeconds)
	conn.Send("SELECT", redisDiscoveryDBIndex)
	conn.Send("SET", psiphonSessionID, string(discoveryRecord), "NX", "EX", discoveryExpireSeconds)
	_, err = conn.Do("EXEC")
	if err != nil {
		return psiphon.ContextError(err)
	}

	return nil
}

var redisPool *redis.Pool

func InitRedis(config *Config) error {
	redisPool = &redis.Pool{
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", config.RedisServerAddress)
		},
		MaxIdle:     REDIS_POOL_MAX_IDLE,
		MaxActive:   REDIS_POOL_MAX_ACTIVE,
		Wait:        false,
		IdleTimeout: REDIS_POOL_IDLE_TIMEOUT,
	}

	// Exercise a connection to the configured redis server so
	// that Init fails if the configuration is incorrect or the
	// server is not responding.
	conn := redisPool.Get()
	_, err := conn.Do("PING")
	conn.Close()

	return err
}
