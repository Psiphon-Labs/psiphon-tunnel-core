// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package ice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/pion/logging"
	"github.com/pion/stun"
	"github.com/pion/transport/v2/test"
	"github.com/pion/transport/v2/vnet"
	"github.com/stretchr/testify/assert"
)

func TestVNetGather(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logging.NewDefaultLoggerFactory()

	t.Run("No local IP address", func(t *testing.T) {
		n, err := vnet.NewNet(&vnet.NetConfig{})
		assert.NoError(t, err)

		a, err := NewAgent(&AgentConfig{
			Net: n,
		})
		assert.NoError(t, err)

		localIPs, err := localInterfaces(a.net, a.interfaceFilter, a.ipFilter, []NetworkType{NetworkTypeUDP4}, false)
		if len(localIPs) > 0 {
			t.Fatal("should return no local IP")
		} else if err != nil {
			t.Fatal(err)
		}

		assert.NoError(t, a.Close())
	})

	t.Run("Gather a dynamic IP address", func(t *testing.T) {
		cider := "1.2.3.0/24"
		_, ipNet, err := net.ParseCIDR(cider)
		if err != nil {
			t.Fatalf("Failed to parse CIDR: %s", err)
		}

		r, err := vnet.NewRouter(&vnet.RouterConfig{
			CIDR:          cider,
			LoggerFactory: loggerFactory,
		})
		if err != nil {
			t.Fatalf("Failed to create a router: %s", err)
		}

		nw, err := vnet.NewNet(&vnet.NetConfig{})
		if err != nil {
			t.Fatalf("Failed to create a Net: %s", err)
		}

		err = r.AddNet(nw)
		if err != nil {
			t.Fatalf("Failed to add a Net to the router: %s", err)
		}

		a, err := NewAgent(&AgentConfig{
			Net: nw,
		})
		assert.NoError(t, err)

		localIPs, err := localInterfaces(a.net, a.interfaceFilter, a.ipFilter, []NetworkType{NetworkTypeUDP4}, false)
		if len(localIPs) == 0 {
			t.Fatal("should have one local IP")
		} else if err != nil {
			t.Fatal(err)
		}

		for _, ip := range localIPs {
			if ip.IsLoopback() {
				t.Fatal("should not return loopback IP")
			}
			if !ipNet.Contains(ip) {
				t.Fatal("should be contained in the CIDR")
			}
		}

		assert.NoError(t, a.Close())
	})

	t.Run("listenUDP", func(t *testing.T) {
		r, err := vnet.NewRouter(&vnet.RouterConfig{
			CIDR:          "1.2.3.0/24",
			LoggerFactory: loggerFactory,
		})
		if err != nil {
			t.Fatalf("Failed to create a router: %s", err)
		}

		nw, err := vnet.NewNet(&vnet.NetConfig{})
		if err != nil {
			t.Fatalf("Failed to create a Net: %s", err)
		}

		err = r.AddNet(nw)
		if err != nil {
			t.Fatalf("Failed to add a Net to the router: %s", err)
		}

		a, err := NewAgent(&AgentConfig{Net: nw})
		if err != nil {
			t.Fatalf("Failed to create agent: %s", err)
		}

		localIPs, err := localInterfaces(a.net, a.interfaceFilter, a.ipFilter, []NetworkType{NetworkTypeUDP4}, false)
		if len(localIPs) == 0 {
			t.Fatal("localInterfaces found no interfaces, unable to test")
		} else if err != nil {
			t.Fatal(err)
		}

		ip := localIPs[0]

		conn, err := listenUDPInPortRange(a.net, a.log, 0, 0, udp, &net.UDPAddr{IP: ip, Port: 0})
		if err != nil {
			t.Fatalf("listenUDP error with no port restriction %v", err)
		} else if conn == nil {
			t.Fatalf("listenUDP error with no port restriction return a nil conn")
		}
		err = conn.Close()
		if err != nil {
			t.Fatalf("failed to close conn")
		}

		_, err = listenUDPInPortRange(a.net, a.log, 4999, 5000, udp, &net.UDPAddr{IP: ip, Port: 0})
		if !errors.Is(err, ErrPort) {
			t.Fatal("listenUDP with invalid port range did not return ErrPort")
		}

		conn, err = listenUDPInPortRange(a.net, a.log, 5000, 5000, udp, &net.UDPAddr{IP: ip, Port: 0})
		if err != nil {
			t.Fatalf("listenUDP error with no port restriction %v", err)
		} else if conn == nil {
			t.Fatalf("listenUDP error with no port restriction return a nil conn")
		}

		_, port, err := net.SplitHostPort(conn.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		} else if port != "5000" {
			t.Fatalf("listenUDP with port restriction of 5000 listened on incorrect port (%s)", port)
		}

		assert.NoError(t, conn.Close())
		assert.NoError(t, a.Close())
	})
}

func TestVNetGatherWithNAT1To1(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logging.NewDefaultLoggerFactory()
	log := loggerFactory.NewLogger("test")

	t.Run("gather 1:1 NAT external IPs as host candidates", func(t *testing.T) {
		externalIP0 := "1.2.3.4"
		externalIP1 := "1.2.3.5"
		localIP0 := "10.0.0.1"
		localIP1 := "10.0.0.2"
		map0 := fmt.Sprintf("%s/%s", externalIP0, localIP0)
		map1 := fmt.Sprintf("%s/%s", externalIP1, localIP1)

		wan, err := vnet.NewRouter(&vnet.RouterConfig{
			CIDR:          "1.2.3.0/24",
			LoggerFactory: loggerFactory,
		})
		assert.NoError(t, err, "should succeed")

		lan, err := vnet.NewRouter(&vnet.RouterConfig{
			CIDR:      "10.0.0.0/24",
			StaticIPs: []string{map0, map1},
			NATType: &vnet.NATType{
				Mode: vnet.NATModeNAT1To1,
			},
			LoggerFactory: loggerFactory,
		})
		assert.NoError(t, err, "should succeed")

		err = wan.AddRouter(lan)
		assert.NoError(t, err, "should succeed")

		nw, err := vnet.NewNet(&vnet.NetConfig{
			StaticIPs: []string{localIP0, localIP1},
		})
		if err != nil {
			t.Fatalf("Failed to create a Net: %s", err)
		}

		err = lan.AddNet(nw)
		assert.NoError(t, err, "should succeed")

		a, err := NewAgent(&AgentConfig{
			NetworkTypes: []NetworkType{
				NetworkTypeUDP4,
			},
			NAT1To1IPs: []string{map0, map1},
			Net:        nw,
		})
		assert.NoError(t, err, "should succeed")
		defer a.Close() //nolint:errcheck

		done := make(chan struct{})
		err = a.OnCandidate(func(c Candidate) {
			if c == nil {
				close(done)
			}
		})
		assert.NoError(t, err, "should succeed")

		err = a.GatherCandidates()
		assert.NoError(t, err, "should succeed")

		log.Debug("Wait until gathering is complete...")
		<-done
		log.Debug("Gathering is done")

		candidates, err := a.GetLocalCandidates()
		assert.NoError(t, err, "should succeed")

		if len(candidates) != 2 {
			t.Fatal("There must be two candidates")
		}

		lAddr := [2]*net.UDPAddr{nil, nil}
		for i, candi := range candidates {
			lAddr[i] = candi.(*CandidateHost).conn.LocalAddr().(*net.UDPAddr) //nolint:forcetypeassert
			if candi.Port() != lAddr[i].Port {
				t.Fatalf("Unexpected candidate port: %d", candi.Port())
			}
		}

		if candidates[0].Address() == externalIP0 {
			if candidates[1].Address() != externalIP1 {
				t.Fatalf("Unexpected candidate IP: %s", candidates[1].Address())
			}
			if lAddr[0].IP.String() != localIP0 {
				t.Fatalf("Unexpected listen IP: %s", lAddr[0].IP.String())
			}
			if lAddr[1].IP.String() != localIP1 {
				t.Fatalf("Unexpected listen IP: %s", lAddr[1].IP.String())
			}
		} else if candidates[0].Address() == externalIP1 {
			if candidates[1].Address() != externalIP0 {
				t.Fatalf("Unexpected candidate IP: %s", candidates[1].Address())
			}
			if lAddr[0].IP.String() != localIP1 {
				t.Fatalf("Unexpected listen IP: %s", lAddr[0].IP.String())
			}
			if lAddr[1].IP.String() != localIP0 {
				t.Fatalf("Unexpected listen IP: %s", lAddr[1].IP.String())
			}
		}
	})

	t.Run("gather 1:1 NAT external IPs as srflx candidates", func(t *testing.T) {
		wan, err := vnet.NewRouter(&vnet.RouterConfig{
			CIDR:          "1.2.3.0/24",
			LoggerFactory: loggerFactory,
		})
		assert.NoError(t, err, "should succeed")

		lan, err := vnet.NewRouter(&vnet.RouterConfig{
			CIDR: "10.0.0.0/24",
			StaticIPs: []string{
				"1.2.3.4/10.0.0.1",
			},
			NATType: &vnet.NATType{
				Mode: vnet.NATModeNAT1To1,
			},
			LoggerFactory: loggerFactory,
		})
		assert.NoError(t, err, "should succeed")

		err = wan.AddRouter(lan)
		assert.NoError(t, err, "should succeed")

		nw, err := vnet.NewNet(&vnet.NetConfig{
			StaticIPs: []string{
				"10.0.0.1",
			},
		})
		if err != nil {
			t.Fatalf("Failed to create a Net: %s", err)
		}

		err = lan.AddNet(nw)
		assert.NoError(t, err, "should succeed")

		a, err := NewAgent(&AgentConfig{
			NetworkTypes: []NetworkType{
				NetworkTypeUDP4,
			},
			NAT1To1IPs: []string{
				"1.2.3.4",
			},
			NAT1To1IPCandidateType: CandidateTypeServerReflexive,
			Net:                    nw,
		})
		assert.NoError(t, err, "should succeed")
		defer a.Close() //nolint:errcheck

		done := make(chan struct{})
		err = a.OnCandidate(func(c Candidate) {
			if c == nil {
				close(done)
			}
		})
		assert.NoError(t, err, "should succeed")

		err = a.GatherCandidates()
		assert.NoError(t, err, "should succeed")

		log.Debug("Wait until gathering is complete...")
		<-done
		log.Debug("Gathering is done")

		candidates, err := a.GetLocalCandidates()
		assert.NoError(t, err, "should succeed")

		if len(candidates) != 2 {
			t.Fatalf("Expected two candidates. actually %d", len(candidates))
		}

		var candiHost *CandidateHost
		var candiSrflx *CandidateServerReflexive

		for _, candidate := range candidates {
			switch candi := candidate.(type) {
			case *CandidateHost:
				candiHost = candi
			case *CandidateServerReflexive:
				candiSrflx = candi
			default:
				t.Fatal("Unexpected candidate type")
			}
		}

		assert.NotNil(t, candiHost, "should not be nil")
		assert.Equal(t, "10.0.0.1", candiHost.Address(), "should match")
		assert.NotNil(t, candiSrflx, "should not be nil")
		assert.Equal(t, "1.2.3.4", candiSrflx.Address(), "should match")
	})
}

func TestVNetGatherWithInterfaceFilter(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logging.NewDefaultLoggerFactory()
	r, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "1.2.3.0/24",
		LoggerFactory: loggerFactory,
	})
	if err != nil {
		t.Fatalf("Failed to create a router: %s", err)
	}

	nw, err := vnet.NewNet(&vnet.NetConfig{})
	if err != nil {
		t.Fatalf("Failed to create a Net: %s", err)
	}

	if err = r.AddNet(nw); err != nil {
		t.Fatalf("Failed to add a Net to the router: %s", err)
	}

	t.Run("InterfaceFilter should exclude the interface", func(t *testing.T) {
		a, err := NewAgent(&AgentConfig{
			Net: nw,
			InterfaceFilter: func(interfaceName string) bool {
				assert.Equal(t, "eth0", interfaceName)
				return false
			},
		})
		assert.NoError(t, err)

		localIPs, err := localInterfaces(a.net, a.interfaceFilter, a.ipFilter, []NetworkType{NetworkTypeUDP4}, false)
		if err != nil {
			t.Fatal(err)
		} else if len(localIPs) != 0 {
			t.Fatal("InterfaceFilter should have excluded everything")
		}

		assert.NoError(t, a.Close())
	})

	t.Run("IPFilter should exclude the IP", func(t *testing.T) {
		a, err := NewAgent(&AgentConfig{
			Net: nw,
			IPFilter: func(ip net.IP) bool {
				assert.Equal(t, net.IP{1, 2, 3, 1}, ip)
				return false
			},
		})
		assert.NoError(t, err)

		localIPs, err := localInterfaces(a.net, a.interfaceFilter, a.ipFilter, []NetworkType{NetworkTypeUDP4}, false)
		if err != nil {
			t.Fatal(err)
		} else if len(localIPs) != 0 {
			t.Fatal("IPFilter should have excluded everything")
		}

		assert.NoError(t, a.Close())
	})

	t.Run("InterfaceFilter should not exclude the interface", func(t *testing.T) {
		a, err := NewAgent(&AgentConfig{
			Net: nw,
			InterfaceFilter: func(interfaceName string) bool {
				assert.Equal(t, "eth0", interfaceName)
				return true
			},
		})
		assert.NoError(t, err)

		localIPs, err := localInterfaces(a.net, a.interfaceFilter, a.ipFilter, []NetworkType{NetworkTypeUDP4}, false)
		if err != nil {
			t.Fatal(err)
		} else if len(localIPs) == 0 {
			t.Fatal("InterfaceFilter should not have excluded anything")
		}

		assert.NoError(t, a.Close())
	})
}

func TestVNetGather_TURNConnectionLeak(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	turnServerURL := &stun.URI{
		Scheme:   stun.SchemeTypeTURN,
		Host:     vnetSTUNServerIP,
		Port:     vnetSTUNServerPort,
		Username: "user",
		Password: "pass",
		Proto:    stun.ProtoTypeUDP,
	}

	// buildVNet with a Symmetric NATs for both LANs
	natType := &vnet.NATType{
		MappingBehavior:   vnet.EndpointAddrPortDependent,
		FilteringBehavior: vnet.EndpointAddrPortDependent,
	}
	v, err := buildVNet(natType, natType)

	if !assert.NoError(t, err, "should succeed") {
		return
	}
	defer v.close()

	cfg0 := &AgentConfig{
		Urls: []*stun.URI{
			turnServerURL,
		},
		NetworkTypes:     supportedNetworkTypes(),
		MulticastDNSMode: MulticastDNSModeDisabled,
		NAT1To1IPs:       []string{vnetGlobalIPA},
		Net:              v.net0,
	}
	aAgent, err := NewAgent(cfg0)
	if !assert.NoError(t, err, "should succeed") {
		return
	}

	aAgent.gatherCandidatesRelay(context.Background(), []*stun.URI{turnServerURL})
	// Assert relay conn leak on close.
	assert.NoError(t, aAgent.Close())
}
