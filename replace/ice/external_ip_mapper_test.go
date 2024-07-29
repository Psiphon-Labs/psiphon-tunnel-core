// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExternalIPMapper(t *testing.T) {
	t.Run("validateIPString", func(t *testing.T) {
		var ip net.IP
		var isIPv4 bool
		var err error

		ip, isIPv4, err = validateIPString("1.2.3.4")
		assert.NoError(t, err, "should succeed")
		assert.True(t, isIPv4, "should be true")
		assert.Equal(t, "1.2.3.4", ip.String(), "should be true")

		ip, isIPv4, err = validateIPString("2601:4567::5678")
		assert.NoError(t, err, "should succeed")
		assert.False(t, isIPv4, "should be false")
		assert.Equal(t, "2601:4567::5678", ip.String(), "should be true")

		_, _, err = validateIPString("bad.6.6.6")
		assert.Error(t, err, "should fail")
	})

	t.Run("newExternalIPMapper", func(t *testing.T) {
		var m *externalIPMapper
		var err error

		// ips being nil should succeed but mapper will be nil also
		m, err = newExternalIPMapper(CandidateTypeUnspecified, nil)
		assert.NoError(t, err, "should succeed")
		assert.Nil(t, m, "should be nil")

		// ips being empty should succeed but mapper will still be nil
		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{})
		assert.NoError(t, err, "should succeed")
		assert.Nil(t, m, "should be nil")

		// IPv4 with no explicit local IP, defaults to CandidateTypeHost
		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"1.2.3.4",
		})
		assert.NoError(t, err, "should succeed")
		assert.NotNil(t, m, "should not be nil")
		assert.Equal(t, CandidateTypeHost, m.candidateType, "should match")
		assert.NotNil(t, m.ipv4Mapping.ipSole)
		assert.Nil(t, m.ipv6Mapping.ipSole)
		assert.Equal(t, 0, len(m.ipv4Mapping.ipMap), "should match")
		assert.Equal(t, 0, len(m.ipv6Mapping.ipMap), "should match")

		// IPv4 with no explicit local IP, using CandidateTypeServerReflexive
		m, err = newExternalIPMapper(CandidateTypeServerReflexive, []string{
			"1.2.3.4",
		})
		assert.NoError(t, err, "should succeed")
		assert.NotNil(t, m, "should not be nil")
		assert.Equal(t, CandidateTypeServerReflexive, m.candidateType, "should match")
		assert.NotNil(t, m.ipv4Mapping.ipSole)
		assert.Nil(t, m.ipv6Mapping.ipSole)
		assert.Equal(t, 0, len(m.ipv4Mapping.ipMap), "should match")
		assert.Equal(t, 0, len(m.ipv6Mapping.ipMap), "should match")

		// IPv4 with no explicit local IP, defaults to CandidateTypeHost
		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"2601:4567::5678",
		})
		assert.NoError(t, err, "should succeed")
		assert.NotNil(t, m, "should not be nil")
		assert.Equal(t, CandidateTypeHost, m.candidateType, "should match")
		assert.Nil(t, m.ipv4Mapping.ipSole)
		assert.NotNil(t, m.ipv6Mapping.ipSole)
		assert.Equal(t, 0, len(m.ipv4Mapping.ipMap), "should match")
		assert.Equal(t, 0, len(m.ipv6Mapping.ipMap), "should match")

		// IPv4 and IPv6 in the mix
		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"1.2.3.4",
			"2601:4567::5678",
		})
		assert.NoError(t, err, "should succeed")
		assert.NotNil(t, m, "should not be nil")
		assert.Equal(t, CandidateTypeHost, m.candidateType, "should match")
		assert.NotNil(t, m.ipv4Mapping.ipSole)
		assert.NotNil(t, m.ipv6Mapping.ipSole)
		assert.Equal(t, 0, len(m.ipv4Mapping.ipMap), "should match")
		assert.Equal(t, 0, len(m.ipv6Mapping.ipMap), "should match")

		// Unsupported candidate type - CandidateTypePeerReflexive
		m, err = newExternalIPMapper(CandidateTypePeerReflexive, []string{
			"1.2.3.4",
		})
		assert.Error(t, err, "should fail")
		assert.Nil(t, m, "should be nil")

		// Unsupported candidate type - CandidateTypeRelay
		m, err = newExternalIPMapper(CandidateTypePeerReflexive, []string{
			"1.2.3.4",
		})
		assert.Error(t, err, "should fail")
		assert.Nil(t, m, "should be nil")

		// Cannot duplicate mapping IPv4 family
		m, err = newExternalIPMapper(CandidateTypeServerReflexive, []string{
			"1.2.3.4",
			"5.6.7.8",
		})
		assert.Error(t, err, "should fail")
		assert.Nil(t, m, "should be nil")

		// Cannot duplicate mapping IPv6 family
		m, err = newExternalIPMapper(CandidateTypeServerReflexive, []string{
			"2201::1",
			"2201::0002",
		})
		assert.Error(t, err, "should fail")
		assert.Nil(t, m, "should be nil")

		// Invalide external IP string
		m, err = newExternalIPMapper(CandidateTypeServerReflexive, []string{
			"bad.2.3.4",
		})
		assert.Error(t, err, "should fail")
		assert.Nil(t, m, "should be nil")

		// Invalide local IP string
		m, err = newExternalIPMapper(CandidateTypeServerReflexive, []string{
			"1.2.3.4/10.0.0.bad",
		})
		assert.Error(t, err, "should fail")
		assert.Nil(t, m, "should be nil")
	})

	t.Run("newExternalIPMapper with explicit local IP", func(t *testing.T) {
		var m *externalIPMapper
		var err error

		// IPv4 with  explicit local IP, defaults to CandidateTypeHost
		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"1.2.3.4/10.0.0.1",
		})
		assert.NoError(t, err, "should succeed")
		assert.NotNil(t, m, "should not be nil")
		assert.Equal(t, CandidateTypeHost, m.candidateType, "should match")
		assert.Nil(t, m.ipv4Mapping.ipSole)
		assert.Nil(t, m.ipv6Mapping.ipSole)
		assert.Equal(t, 1, len(m.ipv4Mapping.ipMap), "should match")
		assert.Equal(t, 0, len(m.ipv6Mapping.ipMap), "should match")

		// Cannot assign two ext IPs for one local IPv4
		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"1.2.3.4/10.0.0.1",
			"1.2.3.5/10.0.0.1",
		})
		assert.Error(t, err, "should fail")
		assert.Nil(t, m, "should be nil")

		// Cannot assign two ext IPs for one local IPv6
		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"2200::1/fe80::1",
			"2200::0002/fe80::1",
		})
		assert.Error(t, err, "should fail")
		assert.Nil(t, m, "should be nil")

		// Cannot mix different IP family in a pair (1)
		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"2200::1/10.0.0.1",
		})
		assert.Error(t, err, "should fail")
		assert.Nil(t, m, "should be nil")

		// Cannot mix different IP family in a pair (2)
		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"1.2.3.4/fe80::1",
		})
		assert.Error(t, err, "should fail")
		assert.Nil(t, m, "should be nil")

		// Invalid pair
		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"1.2.3.4/192.168.0.2/10.0.0.1",
		})
		assert.Error(t, err, "should fail")
		assert.Nil(t, m, "should be nil")
	})

	t.Run("newExternalIPMapper with implicit and explicit local IP", func(t *testing.T) {
		// Mixing implicit and explicit local IPs not allowed
		_, err := newExternalIPMapper(CandidateTypeUnspecified, []string{
			"1.2.3.4",
			"1.2.3.5/10.0.0.1",
		})
		assert.Error(t, err, "should fail")

		// Mixing implicit and explicit local IPs not allowed
		_, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"1.2.3.5/10.0.0.1",
			"1.2.3.4",
		})
		assert.Error(t, err, "should fail")
	})

	t.Run("findExternalIP without explicit local IP", func(t *testing.T) {
		var m *externalIPMapper
		var err error
		var extIP net.IP

		// IPv4 with  explicit local IP, defaults to CandidateTypeHost
		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"1.2.3.4",
			"2200::1",
		})
		assert.NoError(t, err, "should succeed")
		assert.NotNil(t, m, "should not be nil")
		assert.NotNil(t, m.ipv4Mapping.ipSole)
		assert.NotNil(t, m.ipv6Mapping.ipSole)

		// Find external IPv4
		extIP, err = m.findExternalIP("10.0.0.1")
		assert.NoError(t, err, "should succeed")
		assert.Equal(t, "1.2.3.4", extIP.String(), "should match")

		// Find external IPv6
		extIP, err = m.findExternalIP("fe80::0001") // Use '0001' instead of '1' on purpose
		assert.NoError(t, err, "should succeed")
		assert.Equal(t, "2200::1", extIP.String(), "should match")

		// Bad local IP string
		_, err = m.findExternalIP("really.bad")
		assert.Error(t, err, "should fail")
	})

	t.Run("findExternalIP with explicit local IP", func(t *testing.T) {
		var m *externalIPMapper
		var err error
		var extIP net.IP

		// IPv4 with  explicit local IP, defaults to CandidateTypeHost
		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"1.2.3.4/10.0.0.1",
			"1.2.3.5/10.0.0.2",
			"2200::1/fe80::1",
			"2200::2/fe80::2",
		})
		assert.NoError(t, err, "should succeed")
		assert.NotNil(t, m, "should not be nil")

		// Find external IPv4
		extIP, err = m.findExternalIP("10.0.0.1")
		assert.NoError(t, err, "should succeed")
		assert.Equal(t, "1.2.3.4", extIP.String(), "should match")

		extIP, err = m.findExternalIP("10.0.0.2")
		assert.NoError(t, err, "should succeed")
		assert.Equal(t, "1.2.3.5", extIP.String(), "should match")

		_, err = m.findExternalIP("10.0.0.3")
		assert.Error(t, err, "should fail")

		// Find external IPv6
		extIP, err = m.findExternalIP("fe80::0001") // Use '0001' instead of '1' on purpose
		assert.NoError(t, err, "should succeed")
		assert.Equal(t, "2200::1", extIP.String(), "should match")

		extIP, err = m.findExternalIP("fe80::0002") // Use '0002' instead of '2' on purpose
		assert.NoError(t, err, "should succeed")
		assert.Equal(t, "2200::2", extIP.String(), "should match")

		_, err = m.findExternalIP("fe80::3")
		assert.Error(t, err, "should fail")

		// Bad local IP string
		_, err = m.findExternalIP("really.bad")
		assert.Error(t, err, "should fail")
	})

	t.Run("findExternalIP with empty map", func(t *testing.T) {
		var m *externalIPMapper
		var err error

		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"1.2.3.4",
		})
		assert.NoError(t, err, "should succeed")

		// Attempt to find IPv6 that does not exist in the map
		extIP, err := m.findExternalIP("fe80::1")
		assert.NoError(t, err, "should succeed")
		assert.Equal(t, "fe80::1", extIP.String(), "should match")

		m, err = newExternalIPMapper(CandidateTypeUnspecified, []string{
			"2200::1",
		})
		assert.NoError(t, err, "should succeed")

		// Attempt to find IPv4 that does not exist in the map
		extIP, err = m.findExternalIP("10.0.0.1")
		assert.NoError(t, err, "should succeed")
		assert.Equal(t, "10.0.0.1", extIP.String(), "should match")
	})
}
