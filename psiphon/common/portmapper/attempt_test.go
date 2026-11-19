//go:build !js

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

package portmapper

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// serviceBehavior is how a fake gateway's port mapping service behaves.
type serviceBehavior int

const (
	serviceAbsent serviceBehavior = iota
	serviceWorks
	serviceRefuses
)

func (b serviceBehavior) String() string {
	return [...]string{"absent", "works", "refuses"}[b]
}

// testGateway is a fake gateway with each port mapping service set to a
// chosen behavior, and a client pointed at it.
type testGateway struct {
	igd *TestIGD
	c   *Client

	// upnpAdds counts the UPnP AddPortMapping requests received.
	upnpAdds atomic.Int32
}

// newTestGateway starts a gateway whose NAT-PMP, PCP and UPnP services
// behave as given. A gateway that speaks only one of NAT-PMP and PCP answers
// the other with an unsupported-version result. With pxpPortClosed, nothing
// listens on the NAT-PMP/PCP port at all.
func newTestGateway(t *testing.T, pmp, pcp, upnp serviceBehavior, pxpPortClosed bool) *testGateway {
	t.Helper()
	igd, err := NewTestIGD(t, TestIGDOptions{
		PMP:            pmp != serviceAbsent,
		PMPRefuses:     pmp == serviceRefuses,
		PCP:            pcp != serviceAbsent,
		PCPRefuses:     pcp == serviceRefuses,
		UPnP:           upnp != serviceAbsent,
		StrictVersions: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { igd.Close() })

	g := &testGateway{igd: igd}
	refusal := strings.Replace(testAddPortMappingPermanentLease, "725", "718", 1)
	igd.SetUPnPHandler(&upnpServer{
		t:    t,
		Desc: testRootDesc,
		Control: map[string]map[string]any{
			"/ctl/IPConn": {
				"AddPortMapping": func([]byte) (int, string) {
					g.upnpAdds.Add(1)
					if upnp == serviceRefuses {
						return http.StatusInternalServerError, refusal
					}
					return http.StatusOK, testAddPortMappingResponse
				},
				"GetExternalIPAddress": testGetExternalIPAddressResponse,
				"GetStatusInfo":        testGetStatusInfoResponse,
				"DeletePortMapping":    "",
			},
		},
	})

	g.c = newTestClient(t, igd)
	g.c.silenceDeadline = 200 * time.Millisecond
	if pxpPortClosed {
		closed, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		g.c.testPxPPort = uint16(closed.LocalAddr().(*net.UDPAddr).Port)
		closed.Close()
	}
	g.c.SetLocalPort(12345)
	return g
}

// pxpMapRequests returns the number of NAT-PMP and PCP mapping requests the
// gateway has received.
func (g *testGateway) pxpMapRequests() int32 {
	st := g.igd.stats()
	return st.numPMPMapRecv + st.numPCPMapRecv
}

// TestCreateTriesEveryProtocol checks, for every combination of gateway
// services, and for a client with a fresh probe, an old probe and no probe,
// that a create obtains a mapping exactly when some protocol would grant
// one, and that it does not ask a service that is not known to be available
// while one that is known grants the mapping.
func TestCreateTriesEveryProtocol(t *testing.T) {
	type pxpModel struct {
		name       string
		pmp, pcp   serviceBehavior
		portClosed bool
	}
	pxpModels := []pxpModel{
		{name: "no NAT-PMP or PCP"},
		{name: "NAT-PMP/PCP port closed", portClosed: true},
		{name: "NAT-PMP works", pmp: serviceWorks},
		{name: "NAT-PMP refuses", pmp: serviceRefuses},
		{name: "PCP works", pcp: serviceWorks},
		{name: "PCP refuses", pcp: serviceRefuses},
		{name: "NAT-PMP and PCP work", pmp: serviceWorks, pcp: serviceWorks},
		{name: "NAT-PMP refuses and PCP works", pmp: serviceRefuses, pcp: serviceWorks},
		{name: "NAT-PMP works and PCP refuses", pmp: serviceWorks, pcp: serviceRefuses},
	}

	for _, pxp := range pxpModels {
		for _, upnp := range []serviceBehavior{serviceAbsent, serviceWorks, serviceRefuses} {
			for _, probe := range []string{"fresh", "old", "none"} {
				name := fmt.Sprintf("%s, UPnP %v, %s probe", pxp.name, upnp, probe)
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					g := newTestGateway(t, pxp.pmp, pxp.pcp, upnp, pxp.portClosed)

					var clockOffset atomic.Int64
					g.c.now = func() time.Time {
						return time.Now().Add(time.Duration(clockOffset.Load()))
					}
					ctx := context.Background()
					if probe != "none" {
						if _, err := g.c.Probe(ctx); err != nil {
							t.Fatalf("Probe: %v", err)
						}
					}
					if probe == "old" {
						clockOffset.Store(int64(time.Hour))
					}

					pxpRequestsBefore := g.pxpMapRequests()
					_, external, err := g.c.createOrGetMapping(ctx)

					anyWorks := pxp.pmp == serviceWorks || pxp.pcp == serviceWorks || upnp == serviceWorks
					anyRefuses := pxp.pmp == serviceRefuses || pxp.pcp == serviceRefuses || upnp == serviceRefuses
					switch {
					case anyWorks:
						if err != nil {
							t.Fatalf("createOrGetMapping: %v", err)
						}
						if !external.IsValid() {
							t.Fatalf("no external address")
						}
					case anyRefuses:
						if !errors.Is(err, ErrPortMappingRefused) {
							t.Fatalf("createOrGetMapping returned %v, want a refusal", err)
						}
					default:
						if !errors.Is(err, ErrNoPortMappingServices) {
							t.Fatalf("createOrGetMapping returned %v, want no services", err)
						}
					}

					// Discovery finds a service available when it works. One
					// that refuses says so to discovery too, or is found out
					// by the mapping request.
					pxpAvailable := pxp.pmp == serviceWorks || pxp.pcp == serviceWorks
					if pxpAvailable && g.upnpAdds.Load() != 0 {
						t.Errorf("asked UPnP although NAT-PMP or PCP is available and grants the mapping")
					}
					if !pxpAvailable && upnp == serviceWorks && g.pxpMapRequests() != pxpRequestsBefore {
						t.Errorf("asked NAT-PMP or PCP although only UPnP is available and it grants the mapping")
					}
				})
			}
		}
	}
}

// TestPxPFollowsOtherVersion checks that a request in the format the
// gateway does not speak is followed by one in the format it does.
func TestPxPFollowsOtherVersion(t *testing.T) {
	t.Run("NAT-PMP request to a PCP-only gateway", func(t *testing.T) {
		g := newTestGateway(t, serviceAbsent, serviceWorks, serviceAbsent, false)

		// A client whose probe heard nothing asks in the NAT-PMP format
		// first. The gateway lookup comes first, as the first one discards
		// what the client knows.
		g.c.gatewayAndSelfIP()
		g.c.mu.Lock()
		g.c.probed = true
		g.c.mu.Unlock()
		if _, _, err := g.c.createOrGetMapping(context.Background()); err != nil {
			t.Fatalf("createOrGetMapping: %v", err)
		}
		if got := mappingTypeOf(g.c); got != "pcp" {
			t.Errorf("mapping type = %q, want pcp", got)
		}
		if got := g.igd.stats().numPMPMapRecv; got == 0 {
			t.Error("the NAT-PMP format was not asked first")
		}
	})

	t.Run("PCP request to a NAT-PMP-only gateway", func(t *testing.T) {
		g := newTestGateway(t, serviceWorks, serviceAbsent, serviceAbsent, false)

		// Make the client take the gateway for one that speaks PCP. The
		// gateway lookup comes first, as the first one discards what the
		// client knows.
		g.c.gatewayAndSelfIP()
		g.c.mu.Lock()
		g.c.probed = true
		g.c.services[protocolPCP] = ServiceSeen
		g.c.mu.Unlock()
		if _, _, err := g.c.createOrGetMapping(context.Background()); err != nil {
			t.Fatalf("createOrGetMapping: %v", err)
		}
		if got := mappingTypeOf(g.c); got != "pmp" {
			t.Errorf("mapping type = %q, want pmp", got)
		}
		if got := g.igd.stats().numPCPMapRecv; got == 0 {
			t.Error("the PCP format was not asked first")
		}
	})
}

// TestPxPAsksOtherFormatAfterSilence checks that a gateway which speaks only
// one of NAT-PMP and PCP, and ignores a request in the other format instead
// of rejecting it, is still asked in the format it speaks.
func TestPxPAsksOtherFormatAfterSilence(t *testing.T) {
	t.Run("NAT-PMP request to a PCP-only gateway", func(t *testing.T) {
		igd, err := NewTestIGD(t, TestIGDOptions{PCP: true})
		if err != nil {
			t.Fatal(err)
		}
		defer igd.Close()
		c := newTestClient(t, igd)
		c.silenceDeadline = 200 * time.Millisecond
		c.SetLocalPort(12345)

		// A client whose probe heard nothing asks in the NAT-PMP format
		// first. The gateway lookup comes first, as the first one discards
		// what the client knows.
		c.gatewayAndSelfIP()
		c.mu.Lock()
		c.probed = true
		c.mu.Unlock()
		if _, _, err := c.createOrGetMapping(context.Background()); err != nil {
			t.Fatalf("createOrGetMapping: %v", err)
		}
		if got := mappingTypeOf(c); got != "pcp" {
			t.Errorf("mapping type = %q, want pcp", got)
		}
		if got := igd.stats().numPMPMapRecv; got == 0 {
			t.Error("the NAT-PMP format was not asked first")
		}
	})

	t.Run("PCP request to a NAT-PMP-only gateway", func(t *testing.T) {
		igd, err := NewTestIGD(t, TestIGDOptions{PMP: true})
		if err != nil {
			t.Fatal(err)
		}
		defer igd.Close()
		c := newTestClient(t, igd)
		c.knownRequestTimeout = 300 * time.Millisecond
		c.SetLocalPort(12345)

		// Make the client take the gateway for one that speaks PCP. The
		// gateway lookup comes first, as the first one discards what the
		// client knows.
		c.gatewayAndSelfIP()
		c.mu.Lock()
		c.probed = true
		c.services[protocolPCP] = ServiceSeen
		c.mu.Unlock()
		if _, _, err := c.createOrGetMapping(context.Background()); err != nil {
			t.Fatalf("createOrGetMapping: %v", err)
		}
		if got := mappingTypeOf(c); got != "pmp" {
			t.Errorf("mapping type = %q, want pmp", got)
		}
		if got := igd.stats().numPCPMapRecv; got == 0 {
			t.Error("the PCP format was not asked first")
		}
	})
}

// TestFallbackAfterKnownServiceGoesSilent checks that when a service the
// probe saw stops answering, the next protocol is tried soon enough for a
// caller that awaits the mapping for two seconds.
func TestFallbackAfterKnownServiceGoesSilent(t *testing.T) {
	g := newTestGateway(t, serviceWorks, serviceAbsent, serviceWorks, false)
	ctx := context.Background()
	if _, err := g.c.Probe(ctx); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	g.igd.SetDropMapRequests(1000)
	start := time.Now()
	if _, _, err := g.c.createOrGetMapping(ctx); err != nil {
		t.Fatalf("createOrGetMapping: %v", err)
	}
	if got := mappingTypeOf(g.c); got != "upnp" {
		t.Errorf("mapping type = %q, want upnp", got)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("fell back to UPnP after %v, want under 2s", elapsed)
	}
}

// TestSupersededUPnPMappingIsReleased checks that when a renewal ends with a
// mapping on another external port, the UPnP mapping it replaces is deleted
// from the gateway if its forwarding rule still leads to this client, and
// that a UPnP mapping which is simply renewed is not.
func TestSupersededUPnPMappingIsReleased(t *testing.T) {
	type deleteRequest struct {
		ExternalPort uint16 `xml:"NewExternalPort"`
	}

	// ruleOwner is the internal client that the gateway reports for the
	// forwarding rule on the replaced mapping's external port.
	setup := func(t *testing.T, pmp bool, ruleOwner string) (*TestIGD, *Client, *atomic.Bool, chan uint16) {
		igd, err := NewTestIGD(t, TestIGDOptions{PMP: pmp, UPnP: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { igd.Close() })

		addFails := new(atomic.Bool)
		deleted := make(chan uint16, 8)
		refusal := strings.Replace(testAddPortMappingPermanentLease, "725", "718", 1)
		igd.SetUPnPHandler(&upnpServer{
			t:    t,
			Desc: testRootDesc,
			Control: map[string]map[string]any{
				"/ctl/IPConn": {
					"AddPortMapping": func([]byte) (int, string) {
						if addFails.Load() {
							return http.StatusInternalServerError, refusal
						}
						return http.StatusOK, testAddPortMappingResponse
					},
					"GetExternalIPAddress": testGetExternalIPAddressResponse,
					"GetStatusInfo":        testGetStatusInfoResponse,
					"GetSpecificPortMappingEntry": fmt.Sprintf(
						testGetSpecificPortMappingEntryResponse, 12345, ruleOwner),
					"DeletePortMapping": func(body []byte) string {
						var req deleteRequest
						if err := xml.Unmarshal(body, &req); err != nil {
							t.Errorf("bad DeletePortMapping request: %v", err)
						}
						deleted <- req.ExternalPort
						return ""
					},
				},
			},
		})

		c := newTestClient(t, igd)
		c.knownRequestTimeout = 100 * time.Millisecond
		c.silenceDeadline = 100 * time.Millisecond
		c.SetLocalPort(12345)
		if _, err := c.Probe(context.Background()); err != nil {
			t.Fatalf("Probe: %v", err)
		}
		return igd, c, addFails, deleted
	}

	// expireRenewal makes the client's UPnP mapping due for renewal and
	// returns its external port.
	expireRenewal := func(t *testing.T, c *Client) uint16 {
		c.mu.Lock()
		defer c.mu.Unlock()
		m, ok := c.mapping.(*upnpMapping)
		if !ok {
			t.Fatalf("mapping is %T, want a UPnP mapping", c.mapping)
		}
		m.renewAfter = time.Now().Add(-time.Second)
		return m.external.Port()
	}

	// replaceByPMP obtains a UPnP mapping, then renews it so that UPnP
	// refuses and NAT-PMP grants a mapping on another external port. It
	// returns the external port of the replaced UPnP mapping.
	replaceByPMP := func(t *testing.T, igd *TestIGD, c *Client, addFails *atomic.Bool) uint16 {
		ctx := context.Background()

		// NAT-PMP does not answer, so the first mapping comes from UPnP.
		igd.SetDropMapRequests(1000)
		if _, _, err := c.createOrGetMapping(ctx); err != nil {
			t.Fatalf("createOrGetMapping: %v", err)
		}
		upnpPort := expireRenewal(t, c)

		igd.SetDropMapRequests(0)
		addFails.Store(true)
		_, external, err := c.createOrGetMapping(ctx)
		if err != nil {
			t.Fatalf("createOrGetMapping (renew): %v", err)
		}
		if got := mappingTypeOf(c); got != "pmp" {
			t.Fatalf("mapping type = %q, want pmp", got)
		}
		if external.Port() == upnpPort {
			t.Fatalf("NAT-PMP mapped the same external port %d; the test needs another", upnpPort)
		}
		return upnpPort
	}

	_, myIP, _ := testIPAndGateway()

	t.Run("replaced by NAT-PMP on another port", func(t *testing.T) {
		igd, c, addFails, deleted := setup(t, true, myIP.String())
		upnpPort := replaceByPMP(t, igd, c, addFails)
		select {
		case port := <-deleted:
			if port != upnpPort {
				t.Errorf("deleted external port %d, want %d", port, upnpPort)
			}
		default:
			t.Error("the replaced UPnP mapping was not deleted")
		}
	})

	t.Run("replaced, and its port now belongs to another host", func(t *testing.T) {
		igd, c, addFails, deleted := setup(t, true, "1.2.3.99")
		replaceByPMP(t, igd, c, addFails)
		select {
		case port := <-deleted:
			t.Errorf("deleted external port %d, whose rule leads to another host", port)
		default:
		}
	})

	t.Run("renewed by UPnP", func(t *testing.T) {
		_, c, _, deleted := setup(t, false, myIP.String())
		ctx := context.Background()

		if _, _, err := c.createOrGetMapping(ctx); err != nil {
			t.Fatalf("createOrGetMapping: %v", err)
		}
		upnpPort := expireRenewal(t, c)
		_, external, err := c.createOrGetMapping(ctx)
		if err != nil {
			t.Fatalf("createOrGetMapping (renew): %v", err)
		}
		if external.Port() != upnpPort {
			t.Fatalf("renewal moved to external port %d from %d", external.Port(), upnpPort)
		}
		select {
		case port := <-deleted:
			t.Errorf("deleted external port %d of a mapping that was renewed", port)
		default:
		}
	})
}

const testGetSpecificPortMappingEntryResponse = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetSpecificPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewInternalPort>%d</NewInternalPort>
      <NewInternalClient>%s</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription></NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:GetSpecificPortMappingEntryResponse>
  </s:Body>
</s:Envelope>
`

// TestUPnPDoesNotStarveLaterSteps checks that a UPnP device which accepts a
// request and never answers leaves the NAT-PMP/PCP step, which comes after
// it, the time to be asked.
func TestUPnPDoesNotStarveLaterSteps(t *testing.T) {
	igd, err := NewTestIGD(t, TestIGDOptions{PMP: true, UPnP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { igd.Close() })

	var hang atomic.Bool
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	igd.SetUPnPHandler(&upnpServer{
		t:    t,
		Desc: testRootDesc,
		Control: map[string]map[string]any{
			"/ctl/IPConn": {
				"AddPortMapping": testAddPortMappingResponse,
				"GetExternalIPAddress": func([]byte) (int, string) {
					if hang.Load() {
						<-release
					}
					return http.StatusOK, testGetExternalIPAddressResponse
				},
				"GetStatusInfo": testGetStatusInfoResponse,
				"GetSpecificPortMappingEntry": fmt.Sprintf(
					testGetSpecificPortMappingEntryResponse, 12345, "1.2.3.99"),
				"DeletePortMapping": "",
			},
		},
	})

	c := newTestClient(t, igd)
	c.knownRequestTimeout = 200 * time.Millisecond
	c.silenceDeadline = 100 * time.Millisecond
	c.SetLocalPort(12345)
	ctx := context.Background()
	if _, err := c.Probe(ctx); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	// NAT-PMP does not answer, so the first mapping comes from UPnP, and
	// the renewal asks UPnP first.
	igd.SetDropMapRequests(1000)
	if _, _, err := c.createOrGetMapping(ctx); err != nil {
		t.Fatalf("createOrGetMapping: %v", err)
	}
	c.mu.Lock()
	m, ok := c.mapping.(*upnpMapping)
	if ok {
		m.renewAfter = time.Now().Add(-time.Second)
	}
	c.mu.Unlock()
	if !ok {
		t.Fatal("mapping is not a UPnP mapping")
	}

	igd.SetDropMapRequests(0)
	hang.Store(true)
	renewCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if _, _, err := c.createOrGetMapping(renewCtx); err != nil {
		t.Fatalf("createOrGetMapping (renew): %v", err)
	}
	if got := mappingTypeOf(c); got != "pmp" {
		t.Errorf("mapping type = %q, want pmp", got)
	}
}

func mappingTypeOf(c *Client) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mapping == nil {
		return ""
	}
	return c.mapping.MappingType()
}

// TestPxPRetransmits checks that a request to a service the probe saw is
// sent again when it goes unanswered.
func TestPxPRetransmits(t *testing.T) {
	for _, service := range []string{"pmp", "pcp"} {
		t.Run(service, func(t *testing.T) {
			pmp, pcp := serviceWorks, serviceAbsent
			if service == "pcp" {
				pmp, pcp = serviceAbsent, serviceWorks
			}
			g := newTestGateway(t, pmp, pcp, serviceAbsent, false)
			ctx := context.Background()
			if _, err := g.c.Probe(ctx); err != nil {
				t.Fatalf("Probe: %v", err)
			}

			g.igd.SetDropMapRequests(1)
			if _, _, err := g.c.createOrGetMapping(ctx); err != nil {
				t.Fatalf("createOrGetMapping: %v", err)
			}
			if got := mappingTypeOf(g.c); got != service {
				t.Errorf("mapping type = %q, want %q", got, service)
			}
			if got := g.pxpMapRequests(); got != 2 {
				t.Errorf("mapping requests = %d, want 2", got)
			}
		})
	}
}

// TestMappingOutcome checks that every create started by
// GetCachedMappingOrStartCreatingOne reports its outcome.
func TestMappingOutcome(t *testing.T) {
	for _, test := range []struct {
		name string
		upnp serviceBehavior
		want MappingOutcome
	}{
		{"granted", serviceWorks, MappingGranted},
		{"refused", serviceRefuses, MappingRefused},
		{"no answer", serviceAbsent, MappingNoAnswer},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := newTestGateway(t, serviceAbsent, serviceAbsent, test.upnp, false)
			outcomes := make(chan MappingOutcome, 1)
			g.c.SetOnMappingOutcome(func(outcome MappingOutcome) { outcomes <- outcome })
			if _, err := g.c.Probe(context.Background()); err != nil {
				t.Fatalf("Probe: %v", err)
			}

			g.c.GetCachedMappingOrStartCreatingOne()
			select {
			case got := <-outcomes:
				if got != test.want {
					t.Errorf("outcome = %v, want %v", got, test.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no outcome reported")
			}
		})
	}

	t.Run("not reported after Close", func(t *testing.T) {
		g := newTestGateway(t, serviceAbsent, serviceAbsent, serviceAbsent, false)
		outcomes := make(chan MappingOutcome, 1)
		g.c.SetOnMappingOutcome(func(outcome MappingOutcome) { outcomes <- outcome })

		// Close the client while the create waits for the gateway.
		requested := make(chan struct{}, 1)
		g.igd.SetPxPHook(func() {
			select {
			case requested <- struct{}{}:
			default:
			}
		})
		g.c.GetCachedMappingOrStartCreatingOne()
		select {
		case <-requested:
		case <-time.After(5 * time.Second):
			t.Fatal("no mapping request was sent")
		}
		g.c.Close()

		select {
		case got := <-outcomes:
			t.Errorf("outcome %v reported for a closed client", got)
		case <-time.After(2 * g.c.silenceDeadline):
		}
	})
}

// TestPxPPortUnreachable checks that a gateway's report that nothing listens
// on the NAT-PMP/PCP port ends the wait at once.
func TestPxPPortUnreachable(t *testing.T) {
	g := newTestGateway(t, serviceAbsent, serviceAbsent, serviceAbsent, true)
	g.c.silenceDeadline = 5 * time.Second

	start := time.Now()
	_, _, err := g.c.createOrGetMapping(context.Background())
	if !errors.Is(err, ErrNoPortMappingServices) {
		t.Fatalf("createOrGetMapping returned %v, want no services", err)
	}
	if elapsed := time.Since(start); elapsed > g.c.silenceDeadline/2 {
		t.Errorf("waited %v for a port the gateway reported closed", elapsed)
	}
}
