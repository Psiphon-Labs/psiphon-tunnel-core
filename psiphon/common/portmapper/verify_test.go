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
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDiscoveryOutlastsItsAge checks that what a probe learned is still in
// force long after the probe, for the client and for its clones.
func TestDiscoveryOutlastsItsAge(t *testing.T) {
	g := newTestGateway(t, serviceAbsent, serviceAbsent, serviceWorks, false)
	var clockOffset atomic.Int64
	g.c.now = func() time.Time {
		return time.Now().Add(time.Duration(clockOffset.Load()))
	}
	mustProbeUPnP(t, context.Background(), g.c)
	clockOffset.Store(int64(24 * time.Hour))

	for name, c := range map[string]*Client{"client": g.c, "clone": g.c.Clone(nil)} {
		upnp, pmp, pcp := c.RespondingPortMappingTypes()
		if !upnp || pmp || pcp {
			t.Errorf("%s: RespondingPortMappingTypes() = (%v, %v, %v), want (true, false, false)",
				name, upnp, pmp, pcp)
		}
	}
}

// TestCreateRecoversFromGatewayLookupFailure checks that a client whose
// gateway lookup failed once, which discards what it knew about the
// network, maps again once the lookup works.
func TestCreateRecoversFromGatewayLookupFailure(t *testing.T) {
	for _, test := range []struct {
		name      string
		pcp, upnp serviceBehavior
	}{
		{"UPnP gateway", serviceAbsent, serviceWorks},
		{"PCP gateway", serviceWorks, serviceAbsent},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := newTestGateway(t, serviceAbsent, test.pcp, test.upnp, false)
			var lookupFails atomic.Bool
			g.c.SetGatewayLookupFunc(func() (gw, myIP netip.Addr, ok bool) {
				if lookupFails.Load() {
					return netip.Addr{}, netip.Addr{}, false
				}
				return testIPAndGateway()
			})

			ctx := context.Background()
			if _, err := g.c.Probe(ctx); err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if _, _, err := g.c.createOrGetMapping(ctx); err != nil {
				t.Fatalf("createOrGetMapping: %v", err)
			}

			lookupFails.Store(true)
			if _, _, err := g.c.createOrGetMapping(ctx); !errors.Is(err, ErrGatewayRange) {
				t.Fatalf("createOrGetMapping returned %v while the lookup fails, want %v", err, ErrGatewayRange)
			}

			lookupFails.Store(false)
			if _, _, err := g.c.createOrGetMapping(ctx); err != nil {
				t.Fatalf("createOrGetMapping after the lookup recovered: %v", err)
			}
		})
	}
}

// TestProbeDiscardedOnNetworkChange checks that a probe which was in flight
// when this machine's address changed records nothing, so that what it
// learned on the old network is not taken to describe the new one.
func TestProbeDiscardedOnNetworkChange(t *testing.T) {
	g := newTestGateway(t, serviceWorks, serviceAbsent, serviceWorks, false)
	var addressChanged atomic.Bool
	g.c.SetGatewayLookupFunc(func() (gw, myIP netip.Addr, ok bool) {
		gw, myIP, ok = testIPAndGateway()
		if addressChanged.Load() {
			myIP = netip.MustParseAddr("1.2.3.5")
		}
		return gw, myIP, ok
	})

	// Change the address when the probe's first request reaches the
	// gateway, before any reply, and have the client notice at once.
	var once sync.Once
	g.igd.SetPxPHook(func() {
		once.Do(func() {
			addressChanged.Store(true)
			g.c.gatewayAndSelfIP()
		})
	})

	ctx := context.Background()
	res, err := g.c.Probe(ctx)
	if !errors.Is(err, errProbeInvalidated) {
		t.Fatalf("Probe returned %+v, %v, want %v", res, err, errProbeInvalidated)
	}
	if res != (ProbeResult{}) {
		t.Errorf("Probe returned %+v with its error, want no result", res)
	}
	g.c.mu.Lock()
	probed, services, metas := g.c.probed, g.c.services, len(g.c.uPnPMetas)
	g.c.mu.Unlock()
	if probed || services != [3]ServiceState{} || metas != 0 {
		t.Errorf("kept discovery from the old network: probed=%v services=%v UPnP metas=%d",
			probed, services, metas)
	}

	// The next mapping request probes the new network and succeeds.
	if _, _, err := g.c.createOrGetMapping(ctx); err != nil {
		t.Fatalf("createOrGetMapping after the address changed: %v", err)
	}
	g.c.mu.Lock()
	probed = g.c.probed
	g.c.mu.Unlock()
	if !probed {
		t.Error("the new network was not probed")
	}
}

// TestCreateRediscoversUPnPDevice checks that when the UPnP device that
// discovery found stops answering, as after a gateway restarted its UPnP
// service at another address, the next create probes again and maps through
// the device at its new address.
func TestCreateRediscoversUPnPDevice(t *testing.T) {
	before := newTestGateway(t, serviceAbsent, serviceAbsent, serviceWorks, false)
	after := newTestGateway(t, serviceAbsent, serviceAbsent, serviceWorks, false)
	c := before.c
	c.silenceDeadline = 50 * time.Millisecond
	ctx := context.Background()

	if _, err := c.Probe(ctx); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if _, _, err := c.createOrGetMapping(ctx); err != nil {
		t.Fatalf("createOrGetMapping: %v", err)
	}

	// The gateway now serves UPnP elsewhere, and has forgotten the mapping.
	// The first renewal finds nothing where discovery said the device was.
	before.igd.Close()
	c.mu.Lock()
	c.testUPnPPort = after.c.testUPnPPort
	c.testPxPPort = after.c.testPxPPort
	c.mapping.(*upnpMapping).renewAfter = time.Now().Add(-time.Second)
	c.mu.Unlock()
	if _, _, err := c.createOrGetMapping(ctx); !errors.Is(err, ErrNoPortMappingServices) {
		t.Fatalf("createOrGetMapping returned %v after the device moved, want %v", err, ErrNoPortMappingServices)
	}

	// The next one probes again and finds it.
	if _, _, err := c.createOrGetMapping(ctx); err != nil {
		t.Fatalf("createOrGetMapping after rediscovery: %v", err)
	}
	if got := after.upnpAdds.Load(); got != 1 {
		t.Errorf("AddPortMapping requests at the new address = %d, want 1", got)
	}
}

// TestCreateProbesAgainAfterFailure checks that a create which found no
// service, on a network whose probe heard nothing, is followed by one that
// probes again, and so finds a service that the first probe missed.
func TestCreateProbesAgainAfterFailure(t *testing.T) {
	silent := newTestGateway(t, serviceAbsent, serviceAbsent, serviceAbsent, true)
	found := newTestGateway(t, serviceAbsent, serviceAbsent, serviceWorks, false)
	c := silent.c
	ctx := context.Background()

	// Nothing answers the first probe: the UPnP discovery goes to a gateway
	// that has no UPnP, and the NAT-PMP/PCP port is closed.
	if _, _, err := c.createOrGetMapping(ctx); !errors.Is(err, ErrNoPortMappingServices) {
		t.Fatalf("createOrGetMapping returned %v, want %v", err, ErrNoPortMappingServices)
	}

	// The gateway's UPnP service is now there to be found.
	c.mu.Lock()
	c.testUPnPPort = found.c.testUPnPPort
	c.mu.Unlock()
	if _, _, err := c.createOrGetMapping(ctx); err != nil {
		t.Fatalf("createOrGetMapping after the failure: %v", err)
	}
	if got := mappingTypeOf(c); got != "upnp" {
		t.Errorf("mapping type = %q, want upnp", got)
	}
}

// TestCreateUsesNetworkItProbed checks that when this machine's address
// changes between the start of a create and the probe that the create runs
// first, the mapping is requested for the address that was probed.
func TestCreateUsesNetworkItProbed(t *testing.T) {
	g := newTestGateway(t, serviceWorks, serviceAbsent, serviceAbsent, false)
	newIP := netip.MustParseAddr("1.2.3.5")
	var lookups atomic.Int32
	g.c.SetGatewayLookupFunc(func() (gw, myIP netip.Addr, ok bool) {
		gw, myIP, ok = testIPAndGateway()
		if lookups.Add(1) > 1 {
			myIP = newIP
		}
		return gw, myIP, ok
	})

	if _, _, err := g.c.createOrGetMapping(context.Background()); err != nil {
		t.Fatalf("createOrGetMapping: %v", err)
	}
	g.c.mu.Lock()
	m, ok := g.c.mapping.(*pmpMapping)
	g.c.mu.Unlock()
	if !ok {
		t.Fatal("mapping is not a NAT-PMP mapping")
	}
	if got := m.internal.Addr(); got != newIP {
		t.Errorf("mapping requested for %v, want %v", got, newIP)
	}
}

func TestVerify(t *testing.T) {
	for _, test := range []struct {
		name           string
		pmp, pcp, upnp serviceBehavior
		want           Verification
	}{
		{
			name: "UPnP grants",
			upnp: serviceWorks,
			want: Verification{
				UPnP:     ServiceGranted,
				External: netip.MustParseAddr("123.123.123.123"),
			},
		},
		{
			// The gateway answers discovery, and mapping is switched off.
			name: "UPnP is seen and refuses",
			upnp: serviceRefuses,
			want: Verification{UPnP: ServiceRefused},
		},
		{
			name: "NAT-PMP grants and UPnP is not asked",
			pmp:  serviceWorks,
			upnp: serviceWorks,
			want: Verification{
				PMP:      ServiceGranted,
				UPnP:     ServiceSeen,
				External: netip.MustParseAddr("123.123.123.123"),
			},
		},
		{
			name: "NAT-PMP refuses and UPnP grants",
			pmp:  serviceRefuses,
			upnp: serviceWorks,
			want: Verification{
				PMP:      ServiceRefused,
				UPnP:     ServiceGranted,
				External: netip.MustParseAddr("123.123.123.123"),
			},
		},
		{
			// The fake gateway's PCP service maps to a loopback address.
			// The address is reported as the gateway gave it.
			name: "PCP grants",
			pcp:  serviceWorks,
			want: Verification{
				PCP:      ServiceGranted,
				External: netip.MustParseAddr("127.0.0.1"),
			},
		},
		{
			name: "nothing answers",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := newTestGateway(t, test.pmp, test.pcp, test.upnp, false)
			g.c.SetPreferredExternalPort(4567)

			got, err := g.c.Verify(context.Background())
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got != test.want {
				t.Errorf("Verify() = %+v, want %+v", got, test.want)
			}
			if g.c.HaveMapping() {
				t.Error("the trial mapping became the client's mapping")
			}

			// What Verify learned decides which service a clone asks first.
			clone := g.c.Clone(nil)
			clone.SetLocalPort(23456)
			pxpRequestsBefore := g.pxpMapRequests()
			upnpAddsBefore := g.upnpAdds.Load()
			_, _, err = clone.createOrGetMapping(context.Background())
			if (err == nil) != test.want.Granted() {
				t.Fatalf("createOrGetMapping on a clone returned %v, but Granted() = %v", err, test.want.Granted())
			}
			switch {
			case test.want.UPnP == ServiceGranted:
				if g.pxpMapRequests() != pxpRequestsBefore {
					t.Error("the clone asked NAT-PMP or PCP although UPnP granted the trial mapping")
				}
			case test.want.Granted():
				if g.upnpAdds.Load() != upnpAddsBefore {
					t.Error("the clone asked UPnP although NAT-PMP or PCP granted the trial mapping")
				}
			}
		})
	}
}

// TestVerifyReportsOnlyItsOwnGrant checks that a second Verify, whose trial
// mapping gets no answer, does not report the grant of the first.
func TestVerifyReportsOnlyItsOwnGrant(t *testing.T) {
	g := newTestGateway(t, serviceWorks, serviceAbsent, serviceAbsent, false)
	g.c.knownRequestTimeout = 200 * time.Millisecond
	ctx := context.Background()

	v, err := g.c.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.PMP != ServiceGranted {
		t.Fatalf("first Verify() = %+v, want NAT-PMP granted", v)
	}

	g.igd.SetDropMapRequests(1000)
	v, err = g.c.Verify(ctx)
	if err != nil {
		t.Fatalf("second Verify: %v", err)
	}
	if v.Granted() || v.External.IsValid() {
		t.Errorf("second Verify() = %+v, want nothing granted", v)
	}
}

// TestVerifyOutOfTime checks that a trial which is still running when its
// context ends is reported as an error, not as a network that grants no
// mapping.
func TestVerifyOutOfTime(t *testing.T) {
	g := newTestGateway(t, serviceWorks, serviceAbsent, serviceAbsent, false)
	if _, err := g.c.Probe(context.Background()); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	// The trial runs on in the background, so it must not log to t.
	g.c.logf = discardLogf
	g.c.knownRequestTimeout = 200 * time.Millisecond

	g.igd.SetDropMapRequests(1000)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if v, err := g.c.Verify(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Verify() = %+v, %v, want %v", v, err, context.DeadlineExceeded)
	}
}

// TestVerifyCancelledReleasesTrialMapping checks that when Verify is
// cancelled while the gateway is granting the trial mapping, the mapping is
// still released.
func TestVerifyCancelledReleasesTrialMapping(t *testing.T) {
	igd, err := NewTestIGD(t, TestIGDOptions{UPnP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deleted := make(chan struct{}, 1)
	igd.SetUPnPHandler(&upnpServer{
		t:    t,
		Desc: testRootDesc,
		Control: map[string]map[string]any{
			"/ctl/IPConn": {
				"AddPortMapping": func([]byte) (int, string) {
					// Cancel after the gateway has accepted the request,
					// before the caller receives the response.
					cancel()
					return http.StatusOK, testAddPortMappingResponse
				},
				"GetExternalIPAddress": testGetExternalIPAddressResponse,
				"GetStatusInfo":        testGetStatusInfoResponse,
				"DeletePortMapping": func([]byte) string {
					deleted <- struct{}{}
					return ""
				},
			},
		},
	})

	c := newTestClient(t, igd)
	c.silenceDeadline = 50 * time.Millisecond
	if _, err := c.Probe(context.Background()); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	// The trial runs on in the background, so it must not log to t.
	c.logf = discardLogf

	if v, err := c.Verify(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify() = %+v, %v, want %v", v, err, context.Canceled)
	}
	select {
	case <-deleted:
	case <-time.After(5 * time.Second):
		t.Fatal("the trial mapping was not released")
	}
}

// TestVerifyReleasesTrialMapping checks that the trial mapping is asked for
// a port other than the client's, without the preferred external port, and
// is released.
func TestVerifyReleasesTrialMapping(t *testing.T) {
	igd, err := NewTestIGD(t, TestIGDOptions{UPnP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()

	type addRequest struct {
		ExternalPort uint16 `xml:"NewExternalPort"`
		InternalPort uint16 `xml:"NewInternalPort"`
	}
	type deleteRequest struct {
		ExternalPort uint16 `xml:"NewExternalPort"`
	}
	var added atomic.Pointer[addRequest]
	var deleted atomic.Pointer[deleteRequest]
	igd.SetUPnPHandler(&upnpServer{
		t:    t,
		Desc: testRootDesc,
		Control: map[string]map[string]any{
			"/ctl/IPConn": {
				"AddPortMapping": func(body []byte) string {
					var req addRequest
					if err := xml.Unmarshal(body, &req); err != nil {
						t.Errorf("bad AddPortMapping request: %v", err)
					}
					added.Store(&req)
					return testAddPortMappingResponse
				},
				"GetExternalIPAddress": testGetExternalIPAddressResponse,
				"GetStatusInfo":        testGetStatusInfoResponse,
				"DeletePortMapping": func(body []byte) string {
					var req deleteRequest
					if err := xml.Unmarshal(body, &req); err != nil {
						t.Errorf("bad DeletePortMapping request: %v", err)
					}
					deleted.Store(&req)
					return ""
				},
			},
		},
	})

	c := newTestClient(t, igd)
	c.SetLocalPort(12345)
	c.SetPreferredExternalPort(4567)
	v, err := c.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !v.Granted() {
		t.Fatalf("Verify() = %+v, want a granted trial mapping", v)
	}

	add, del := added.Load(), deleted.Load()
	if add == nil {
		t.Fatal("no mapping was requested")
	}
	if add.InternalPort == 12345 || add.InternalPort == 0 {
		t.Errorf("trial mapping internal port = %d, want a port reserved for the trial", add.InternalPort)
	}
	if add.ExternalPort == 4567 {
		t.Error("the trial mapping asked for the preferred external port")
	}
	if del == nil {
		t.Fatal("the trial mapping was not released")
	}
	if del.ExternalPort != add.ExternalPort {
		t.Errorf("released external port %d, want %d", del.ExternalPort, add.ExternalPort)
	}
}
