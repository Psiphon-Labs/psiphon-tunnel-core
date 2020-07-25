/*
 * Copyright (c) 2018, Psiphon Inc.
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

package parameters

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func TestGetDefaultParameters(t *testing.T) {

	p, err := NewClientParameters(nil)
	if err != nil {
		t.Fatalf("NewClientParameters failed: %s", err)
	}

	for name, defaults := range defaultClientParameters {
		switch v := defaults.value.(type) {
		case string:
			g := p.Get().String(name)
			if v != g {
				t.Fatalf("String returned %+v expected %+v", g, v)
			}
		case int:
			g := p.Get().Int(name)
			if v != g {
				t.Fatalf("Int returned %+v expected %+v", g, v)
			}
		case float64:
			g := p.Get().Float(name)
			if v != g {
				t.Fatalf("Float returned %+v expected %+v", g, v)
			}
		case bool:
			g := p.Get().Bool(name)
			if v != g {
				t.Fatalf("Bool returned %+v expected %+v", g, v)
			}
		case time.Duration:
			g := p.Get().Duration(name)
			if v != g {
				t.Fatalf("Duration returned %+v expected %+v", g, v)
			}
		case protocol.TunnelProtocols:
			g := p.Get().TunnelProtocols(name)
			if !reflect.DeepEqual(v, g) {
				t.Fatalf("TunnelProtocols returned %+v expected %+v", g, v)
			}
		case protocol.TLSProfiles:
			g := p.Get().TLSProfiles(name)
			if !reflect.DeepEqual(v, g) {
				t.Fatalf("TLSProfiles returned %+v expected %+v", g, v)
			}
		case protocol.LabeledTLSProfiles:
			for label, profiles := range v {
				g := p.Get().LabeledTLSProfiles(name, label)
				if !reflect.DeepEqual(profiles, g) {
					t.Fatalf("LabeledTLSProfiles returned %+v expected %+v", g, profiles)
				}
			}
		case protocol.QUICVersions:
			g := p.Get().QUICVersions(name)
			if !reflect.DeepEqual(v, g) {
				t.Fatalf("QUICVersions returned %+v expected %+v", g, v)
			}
		case protocol.LabeledQUICVersions:
			for label, versions := range v {
				g := p.Get().LabeledTLSProfiles(name, label)
				if !reflect.DeepEqual(versions, g) {
					t.Fatalf("LabeledQUICVersions returned %+v expected %+v", g, versions)
				}
			}
		case TransferURLs:
			g := p.Get().TransferURLs(name)
			if !reflect.DeepEqual(v, g) {
				t.Fatalf("TransferURLs returned %+v expected %+v", g, v)
			}
		case common.RateLimits:
			g := p.Get().RateLimits(name)
			if !reflect.DeepEqual(v, g) {
				t.Fatalf("RateLimits returned %+v expected %+v", g, v)
			}
		case http.Header:
			g := p.Get().HTTPHeaders(name)
			if !reflect.DeepEqual(v, g) {
				t.Fatalf("HTTPHeaders returned %+v expected %+v", g, v)
			}
		case protocol.CustomTLSProfiles:
			g := p.Get().CustomTLSProfileNames()
			names := make([]string, len(v))
			for i, profile := range v {
				names[i] = profile.Name
			}
			if !reflect.DeepEqual(names, g) {
				t.Fatalf("CustomTLSProfileNames returned %+v expected %+v", g, names)
			}
		case KeyValues:
			g := p.Get().KeyValues(name)
			if !reflect.DeepEqual(v, g) {
				t.Fatalf("KeyValues returned %+v expected %+v", g, v)
			}
		case *BPFProgramSpec:
			ok, name, rawInstructions := p.Get().BPFProgram(name)
			if v != nil || ok || name != "" || rawInstructions != nil {
				t.Fatalf(
					"BPFProgramSpec returned %+v %+v %+v expected %+v",
					ok, name, rawInstructions, v)
			}
		default:
			t.Fatalf("Unhandled default type: %s", name)
		}
	}
}

func TestGetValueLogger(t *testing.T) {

	loggerCalled := false

	p, err := NewClientParameters(
		func(error) {
			loggerCalled = true
		})
	if err != nil {
		t.Fatalf("NewClientParameters failed: %s", err)
	}

	p.Get().Int("unknown-parameter-name")

	if !loggerCalled {
		t.Fatalf("logged not called")
	}
}

func TestOverrides(t *testing.T) {

	tag := "tag"
	applyParameters := make(map[string]interface{})

	// Below minimum, should not apply
	defaultConnectionWorkerPoolSize := defaultClientParameters[ConnectionWorkerPoolSize].value.(int)
	minimumConnectionWorkerPoolSize := defaultClientParameters[ConnectionWorkerPoolSize].minimum.(int)
	newConnectionWorkerPoolSize := minimumConnectionWorkerPoolSize - 1
	applyParameters[ConnectionWorkerPoolSize] = newConnectionWorkerPoolSize

	// Above minimum, should apply
	defaultInitialLimitTunnelProtocolsCandidateCount := defaultClientParameters[InitialLimitTunnelProtocolsCandidateCount].value.(int)
	minimumInitialLimitTunnelProtocolsCandidateCount := defaultClientParameters[InitialLimitTunnelProtocolsCandidateCount].minimum.(int)
	newInitialLimitTunnelProtocolsCandidateCount := minimumInitialLimitTunnelProtocolsCandidateCount + 1
	applyParameters[InitialLimitTunnelProtocolsCandidateCount] = newInitialLimitTunnelProtocolsCandidateCount

	p, err := NewClientParameters(nil)
	if err != nil {
		t.Fatalf("NewClientParameters failed: %s", err)
	}

	// No skip on error; should fail and not apply any changes

	_, err = p.Set(tag, false, applyParameters)
	if err == nil {
		t.Fatalf("Set succeeded unexpectedly")
	}

	if p.Get().Tag() != "" {
		t.Fatalf("GetTag returned unexpected value")
	}

	v := p.Get().Int(ConnectionWorkerPoolSize)
	if v != defaultConnectionWorkerPoolSize {
		t.Fatalf("GetInt returned unexpected ConnectionWorkerPoolSize: %d", v)
	}

	v = p.Get().Int(InitialLimitTunnelProtocolsCandidateCount)
	if v != defaultInitialLimitTunnelProtocolsCandidateCount {
		t.Fatalf("GetInt returned unexpected InitialLimitTunnelProtocolsCandidateCount: %d", v)
	}

	// Skip on error; should skip ConnectionWorkerPoolSize and apply InitialLimitTunnelProtocolsCandidateCount

	counts, err := p.Set(tag, true, applyParameters)
	if err != nil {
		t.Fatalf("Set failed: %s", err)
	}

	if counts[0] != 1 {
		t.Fatalf("Apply returned unexpected count: %d", counts[0])
	}

	v = p.Get().Int(ConnectionWorkerPoolSize)
	if v != defaultConnectionWorkerPoolSize {
		t.Fatalf("GetInt returned unexpected ConnectionWorkerPoolSize: %d", v)
	}

	v = p.Get().Int(InitialLimitTunnelProtocolsCandidateCount)
	if v != newInitialLimitTunnelProtocolsCandidateCount {
		t.Fatalf("GetInt returned unexpected InitialLimitTunnelProtocolsCandidateCount: %d", v)
	}
}

func TestNetworkLatencyMultiplier(t *testing.T) {
	p, err := NewClientParameters(nil)
	if err != nil {
		t.Fatalf("NewClientParameters failed: %s", err)
	}

	timeout1 := p.Get().Duration(TunnelConnectTimeout)

	applyParameters := map[string]interface{}{"NetworkLatencyMultiplier": 2.0}

	_, err = p.Set("", false, applyParameters)
	if err != nil {
		t.Fatalf("Set failed: %s", err)
	}

	timeout2 := p.Get().Duration(TunnelConnectTimeout)

	if 2*timeout1 != timeout2 {
		t.Fatalf("Unexpected timeouts: 2 * %s != %s", timeout1, timeout2)
	}
}

func TestCustomNetworkLatencyMultiplier(t *testing.T) {
	p, err := NewClientParameters(nil)
	if err != nil {
		t.Fatalf("NewClientParameters failed: %s", err)
	}

	timeout1 := p.Get().Duration(TunnelConnectTimeout)

	applyParameters := map[string]interface{}{"NetworkLatencyMultiplier": 2.0}

	_, err = p.Set("", false, applyParameters)
	if err != nil {
		t.Fatalf("Set failed: %s", err)
	}

	timeout2 := p.GetCustom(4.0).Duration(TunnelConnectTimeout)

	if 4*timeout1 != timeout2 {
		t.Fatalf("Unexpected timeouts: 4 * %s != %s", timeout1, timeout2)
	}
}

func TestLimitTunnelProtocolProbability(t *testing.T) {
	p, err := NewClientParameters(nil)
	if err != nil {
		t.Fatalf("NewClientParameters failed: %s", err)
	}

	// Default probability should be 1.0 and always return tunnelProtocols

	tunnelProtocols := protocol.TunnelProtocols{"OSSH", "SSH"}

	applyParameters := map[string]interface{}{
		"LimitTunnelProtocols": tunnelProtocols,
	}

	_, err = p.Set("", false, applyParameters)
	if err != nil {
		t.Fatalf("Set failed: %s", err)
	}

	for i := 0; i < 1000; i++ {
		l := p.Get().TunnelProtocols(LimitTunnelProtocols)
		if !reflect.DeepEqual(l, tunnelProtocols) {
			t.Fatalf("unexpected %+v != %+v", l, tunnelProtocols)
		}
	}

	// With probability set to 0.5, should return tunnelProtocols ~50%

	defaultLimitTunnelProtocols := protocol.TunnelProtocols{}

	applyParameters = map[string]interface{}{
		"LimitTunnelProtocolsProbability": 0.5,
		"LimitTunnelProtocols":            tunnelProtocols,
	}

	_, err = p.Set("", false, applyParameters)
	if err != nil {
		t.Fatalf("Set failed: %s", err)
	}

	matchCount := 0

	for i := 0; i < 1000; i++ {
		l := p.Get().TunnelProtocols(LimitTunnelProtocols)
		if reflect.DeepEqual(l, tunnelProtocols) {
			matchCount += 1
		} else if !reflect.DeepEqual(l, defaultLimitTunnelProtocols) {
			t.Fatalf("unexpected %+v != %+v", l, defaultLimitTunnelProtocols)
		}
	}

	if matchCount < 250 || matchCount > 750 {
		t.Fatalf("Unexpected probability result: %d", matchCount)
	}
}

func TestLabeledLists(t *testing.T) {
	p, err := NewClientParameters(nil)
	if err != nil {
		t.Fatalf("NewClientParameters failed: %s", err)
	}

	tlsProfiles := make(protocol.TLSProfiles, 0)
	for i, tlsProfile := range protocol.SupportedTLSProfiles {
		if i%2 == 0 {
			tlsProfiles = append(tlsProfiles, tlsProfile)
		}
	}

	quicVersions := make(protocol.QUICVersions, 0)
	for i, quicVersion := range protocol.SupportedQUICVersions {
		if i%2 == 0 {
			quicVersions = append(quicVersions, quicVersion)
		}
	}

	applyParameters := map[string]interface{}{
		"DisableFrontingProviderTLSProfiles":  protocol.LabeledTLSProfiles{"validLabel": tlsProfiles},
		"DisableFrontingProviderQUICVersions": protocol.LabeledQUICVersions{"validLabel": quicVersions},
	}

	_, err = p.Set("", false, applyParameters)
	if err != nil {
		t.Fatalf("Set failed: %s", err)
	}

	disableTLSProfiles := p.Get().LabeledTLSProfiles(DisableFrontingProviderTLSProfiles, "validLabel")
	if !reflect.DeepEqual(disableTLSProfiles, tlsProfiles) {
		t.Fatalf("LabeledTLSProfiles returned %+v expected %+v", disableTLSProfiles, tlsProfiles)
	}

	disableTLSProfiles = p.Get().LabeledTLSProfiles(DisableFrontingProviderTLSProfiles, "invalidLabel")
	if disableTLSProfiles != nil {
		t.Fatalf("LabeledTLSProfiles returned unexpected non-empty list %+v", disableTLSProfiles)
	}

	disableQUICVersions := p.Get().LabeledQUICVersions(DisableFrontingProviderQUICVersions, "validLabel")
	if !reflect.DeepEqual(disableQUICVersions, quicVersions) {
		t.Fatalf("LabeledQUICVersions returned %+v expected %+v", disableQUICVersions, quicVersions)
	}

	disableQUICVersions = p.Get().LabeledQUICVersions(DisableFrontingProviderQUICVersions, "invalidLabel")
	if disableQUICVersions != nil {
		t.Fatalf("LabeledQUICVersions returned unexpected non-empty list %+v", disableQUICVersions)
	}
}

func TestCustomTLSProfiles(t *testing.T) {
	p, err := NewClientParameters(nil)
	if err != nil {
		t.Fatalf("NewClientParameters failed: %s", err)
	}

	customTLSProfiles := protocol.CustomTLSProfiles{
		&protocol.CustomTLSProfile{Name: "Profile1", UTLSSpec: &protocol.UTLSSpec{}},
		&protocol.CustomTLSProfile{Name: "Profile2", UTLSSpec: &protocol.UTLSSpec{}},
	}

	applyParameters := map[string]interface{}{
		"CustomTLSProfiles": customTLSProfiles}

	_, err = p.Set("", false, applyParameters)
	if err != nil {
		t.Fatalf("Set failed: %s", err)
	}

	names := p.Get().CustomTLSProfileNames()

	if len(names) != 2 || names[0] != "Profile1" || names[1] != "Profile2" {
		t.Fatalf("Unexpected CustomTLSProfileNames: %+v", names)
	}

	profile := p.Get().CustomTLSProfile("Profile1")
	if profile == nil || profile.Name != "Profile1" {
		t.Fatalf("Unexpected profile")
	}

	profile = p.Get().CustomTLSProfile("Profile2")
	if profile == nil || profile.Name != "Profile2" {
		t.Fatalf("Unexpected profile")
	}

	profile = p.Get().CustomTLSProfile("Profile3")
	if profile != nil {
		t.Fatalf("Unexpected profile")
	}
}

func TestApplicationParameters(t *testing.T) {

	parametersJSON := []byte(`
    {
       "ApplicationParameters" : {
         "AppFlag1" : true,
         "AppConfig1" : {"Option1" : "A", "Option2" : "B"},
         "AppSwitches1" : [1, 2, 3, 4]
       }
    }
    `)

	validators := map[string]func(v interface{}) bool{
		"AppFlag1": func(v interface{}) bool { return reflect.DeepEqual(v, true) },
		"AppConfig1": func(v interface{}) bool {
			return reflect.DeepEqual(v, map[string]interface{}{"Option1": "A", "Option2": "B"})
		},
		"AppSwitches1": func(v interface{}) bool {
			return reflect.DeepEqual(v, []interface{}{float64(1), float64(2), float64(3), float64(4)})
		},
	}

	var applyParameters map[string]interface{}
	err := json.Unmarshal(parametersJSON, &applyParameters)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s", err)
	}

	p, err := NewClientParameters(nil)
	if err != nil {
		t.Fatalf("NewClientParameters failed: %s", err)
	}

	_, err = p.Set("", false, applyParameters)
	if err != nil {
		t.Fatalf("Set failed: %s", err)
	}

	keyValues := p.Get().KeyValues(ApplicationParameters)

	if len(keyValues) != len(validators) {
		t.Fatalf("Unexpected key value count")
	}

	for key, value := range keyValues {

		validator, ok := validators[key]
		if !ok {
			t.Fatalf("Unexpected key: %s", key)
		}

		var unmarshaledValue interface{}
		err := json.Unmarshal(value, &unmarshaledValue)
		if err != nil {
			t.Fatalf("Unmarshal failed: %s", err)
		}

		if !validator(unmarshaledValue) {
			t.Fatalf("Invalid value: %s, %T: %+v",
				key, unmarshaledValue, unmarshaledValue)
		}
	}
}
