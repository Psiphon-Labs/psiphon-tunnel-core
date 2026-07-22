//go:build !js

// (no raw sockets in JS/WASM)

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

// This file is part of a hard fork of Tailscale's net/portmapper; see the
// package documentation in portmapper.go. Copied from tailscale v1.98.5:
//
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/portmapper/legacy_upnp.go
//
// The original Tailscale code is licensed as follows:
//
//	Copyright (c) Tailscale Inc & contributors
//	SPDX-License-Identifier: BSD-3-Clause

package portmapper

import (
	"context"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/soap"
)

const (
	urn_LegacyWANPPPConnection_1 = "urn:dslforum-org:service:WANPPPConnection:1"
	urn_LegacyWANIPConnection_1  = "urn:dslforum-org:service:WANIPConnection:1"
)

// legacyWANPPPConnection1 is the same as internetgateway2.WANPPPConnection1,
// except using the old URN that starts with "urn:dslforum-org".
//
// The definition for this can be found in older documentation about UPnP; for
// the purposes of this implementation, we're referring to "DSL Forum TR-064:
// LAN-Side DSL CPE Configuration", which, while deprecated, can be found at:
//
//	https://www.broadband-forum.org/wp-content/uploads/2018/11/TR-064_Corrigendum-1.pdf
//	https://www.broadband-forum.org/pdfs/tr-064-1-0-1.pdf
type legacyWANPPPConnection1 struct {
	goupnp.ServiceClient
}

// AddPortMappingCtx implements upnpClient
func (client *legacyWANPPPConnection1) AddPortMappingCtx(
	ctx context.Context,
	NewRemoteHost string,
	NewExternalPort uint16,
	NewProtocol string,
	NewInternalPort uint16,
	NewInternalClient string,
	NewEnabled bool,
	NewPortMappingDescription string,
	NewLeaseDuration uint32,
) (err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost             string
		NewExternalPort           string
		NewProtocol               string
		NewInternalPort           string
		NewInternalClient         string
		NewEnabled                string
		NewPortMappingDescription string
		NewLeaseDuration          string
	}{}

	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	if request.NewInternalPort, err = soap.MarshalUi2(NewInternalPort); err != nil {
		return
	}
	if request.NewInternalClient, err = soap.MarshalString(NewInternalClient); err != nil {
		return
	}
	if request.NewEnabled, err = soap.MarshalBoolean(NewEnabled); err != nil {
		return
	}
	if request.NewPortMappingDescription, err = soap.MarshalString(NewPortMappingDescription); err != nil {
		return
	}
	if request.NewLeaseDuration, err = soap.MarshalUi4(NewLeaseDuration); err != nil {
		return
	}

	// Response structure.
	response := any(nil)

	// Perform the SOAP call.
	return client.SOAPClient.PerformActionCtx(ctx, urn_LegacyWANPPPConnection_1, "AddPortMapping", request, response)
}

// DeletePortMappingCtx implements upnpClient
func (client *legacyWANPPPConnection1) DeletePortMappingCtx(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string) (err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost   string
		NewExternalPort string
		NewProtocol     string
	}{}
	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}

	// Response structure.
	response := any(nil)

	// Perform the SOAP call.
	return client.SOAPClient.PerformActionCtx(ctx, urn_LegacyWANPPPConnection_1, "DeletePortMapping", request, response)
}

// GetExternalIPAddressCtx implements upnpClient
func (client *legacyWANPPPConnection1) GetExternalIPAddressCtx(ctx context.Context) (NewExternalIPAddress string, err error) {
	// Request structure.
	request := any(nil)

	// Response structure.
	response := &struct {
		NewExternalIPAddress string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformActionCtx(ctx, urn_LegacyWANPPPConnection_1, "GetExternalIPAddress", request, response); err != nil {
		return
	}

	if NewExternalIPAddress, err = soap.UnmarshalString(response.NewExternalIPAddress); err != nil {
		return
	}
	return
}

// GetStatusInfoCtx implements upnpClient
func (client *legacyWANPPPConnection1) GetStatusInfoCtx(ctx context.Context) (NewConnectionStatus string, NewLastConnectionError string, NewUptime uint32, err error) {
	// Request structure.
	request := any(nil)

	// Response structure.
	response := &struct {
		NewConnectionStatus    string
		NewLastConnectionError string
		NewUpTime              string // NOTE: the "T" is capitalized here, per the spec, though it's lowercase in the newer UPnP spec
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformActionCtx(ctx, urn_LegacyWANPPPConnection_1, "GetStatusInfo", request, response); err != nil {
		return
	}

	if NewConnectionStatus, err = soap.UnmarshalString(response.NewConnectionStatus); err != nil {
		return
	}
	if NewLastConnectionError, err = soap.UnmarshalString(response.NewLastConnectionError); err != nil {
		return
	}
	if NewUptime, err = soap.UnmarshalUi4(response.NewUpTime); err != nil {
		return
	}
	return
}

// legacyWANIPConnection1 is the same as internetgateway2.WANIPConnection1,
// except using the old URN that starts with "urn:dslforum-org".
//
// See legacyWANPPPConnection1 for details on where this is defined.
type legacyWANIPConnection1 struct {
	goupnp.ServiceClient
}

// AddPortMappingCtx implements upnpClient
func (client *legacyWANIPConnection1) AddPortMappingCtx(
	ctx context.Context,
	NewRemoteHost string,
	NewExternalPort uint16,
	NewProtocol string,
	NewInternalPort uint16,
	NewInternalClient string,
	NewEnabled bool,
	NewPortMappingDescription string,
	NewLeaseDuration uint32,
) (err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost             string
		NewExternalPort           string
		NewProtocol               string
		NewInternalPort           string
		NewInternalClient         string
		NewEnabled                string
		NewPortMappingDescription string
		NewLeaseDuration          string
	}{}

	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	if request.NewInternalPort, err = soap.MarshalUi2(NewInternalPort); err != nil {
		return
	}
	if request.NewInternalClient, err = soap.MarshalString(NewInternalClient); err != nil {
		return
	}
	if request.NewEnabled, err = soap.MarshalBoolean(NewEnabled); err != nil {
		return
	}
	if request.NewPortMappingDescription, err = soap.MarshalString(NewPortMappingDescription); err != nil {
		return
	}
	if request.NewLeaseDuration, err = soap.MarshalUi4(NewLeaseDuration); err != nil {
		return
	}

	// Response structure.
	response := any(nil)

	// Perform the SOAP call.
	return client.SOAPClient.PerformActionCtx(ctx, urn_LegacyWANIPConnection_1, "AddPortMapping", request, response)
}

// DeletePortMappingCtx implements upnpClient
func (client *legacyWANIPConnection1) DeletePortMappingCtx(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string) (err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost   string
		NewExternalPort string
		NewProtocol     string
	}{}
	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}

	// Response structure.
	response := any(nil)

	// Perform the SOAP call.
	return client.SOAPClient.PerformActionCtx(ctx, urn_LegacyWANIPConnection_1, "DeletePortMapping", request, response)
}

// GetExternalIPAddressCtx implements upnpClient
func (client *legacyWANIPConnection1) GetExternalIPAddressCtx(ctx context.Context) (NewExternalIPAddress string, err error) {
	// Request structure.
	request := any(nil)

	// Response structure.
	response := &struct {
		NewExternalIPAddress string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformActionCtx(ctx, urn_LegacyWANIPConnection_1, "GetExternalIPAddress", request, response); err != nil {
		return
	}

	if NewExternalIPAddress, err = soap.UnmarshalString(response.NewExternalIPAddress); err != nil {
		return
	}
	return
}

// GetStatusInfoCtx implements upnpClient
func (client *legacyWANIPConnection1) GetStatusInfoCtx(ctx context.Context) (NewConnectionStatus string, NewLastConnectionError string, NewUptime uint32, err error) {
	// Request structure.
	request := any(nil)

	// Response structure.
	response := &struct {
		NewConnectionStatus    string
		NewLastConnectionError string
		NewUpTime              string // NOTE: the "T" is capitalized here, per the spec, though it's lowercase in the newer UPnP spec
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformActionCtx(ctx, urn_LegacyWANIPConnection_1, "GetStatusInfo", request, response); err != nil {
		return
	}

	if NewConnectionStatus, err = soap.UnmarshalString(response.NewConnectionStatus); err != nil {
		return
	}
	if NewLastConnectionError, err = soap.UnmarshalString(response.NewLastConnectionError); err != nil {
		return
	}
	if NewUptime, err = soap.UnmarshalUi4(response.NewUpTime); err != nil {
		return
	}
	return
}
