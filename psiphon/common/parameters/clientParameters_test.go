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
				t.Fatalf("GetString returned %+v expected %+v", v, g)
			}
		case int:
			g := p.Get().Int(name)
			if v != g {
				t.Fatalf("GetInt returned %+v expected %+v", v, g)
			}
		case float64:
			g := p.Get().Float(name)
			if v != g {
				t.Fatalf("GetFloat returned %+v expected %+v", v, g)
			}
		case bool:
			g := p.Get().Bool(name)
			if v != g {
				t.Fatalf("GetBool returned %+v expected %+v", v, g)
			}
		case time.Duration:
			g := p.Get().Duration(name)
			if v != g {
				t.Fatalf("GetDuration returned %+v expected %+v", v, g)
			}
		case protocol.TunnelProtocols:
			g := p.Get().TunnelProtocols(name)
			if !reflect.DeepEqual(v, g) {
				t.Fatalf("GetTunnelProtocols returned %+v expected %+v", v, g)
			}
		case DownloadURLs:
			g := p.Get().DownloadURLs(name)
			if !reflect.DeepEqual(v, g) {
				t.Fatalf("GetDownloadURLs returned %+v expected %+v", v, g)
			}
		case common.RateLimits:
			g := p.Get().RateLimits(name)
			if !reflect.DeepEqual(v, g) {
				t.Fatalf("GetRateLimits returned %+v expected %+v", v, g)
			}
		case http.Header:
			g := p.Get().HTTPHeaders(name)
			if !reflect.DeepEqual(v, g) {
				t.Fatalf("GetHTTPHeaders returned %+v expected %+v", v, g)
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
	defaultPrioritizeTunnelProtocolsCandidateCount := defaultClientParameters[PrioritizeTunnelProtocolsCandidateCount].value.(int)
	minimumPrioritizeTunnelProtocolsCandidateCount := defaultClientParameters[PrioritizeTunnelProtocolsCandidateCount].minimum.(int)
	newPrioritizeTunnelProtocolsCandidateCount := minimumPrioritizeTunnelProtocolsCandidateCount + 1
	applyParameters[PrioritizeTunnelProtocolsCandidateCount] = newPrioritizeTunnelProtocolsCandidateCount

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

	v = p.Get().Int(PrioritizeTunnelProtocolsCandidateCount)
	if v != defaultPrioritizeTunnelProtocolsCandidateCount {
		t.Fatalf("GetInt returned unexpected PrioritizeTunnelProtocolsCandidateCount: %d", v)
	}

	// Skip on error; should skip ConnectionWorkerPoolSize and apply PrioritizeTunnelProtocolsCandidateCount

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

	v = p.Get().Int(PrioritizeTunnelProtocolsCandidateCount)
	if v != newPrioritizeTunnelProtocolsCandidateCount {
		t.Fatalf("GetInt returned unexpected PrioritizeTunnelProtocolsCandidateCount: %d", v)
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
