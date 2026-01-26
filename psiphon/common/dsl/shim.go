/*
 * Copyright (c) 2025, Psiphon Inc.
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

package dsl

import (
	"unsafe"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/fxamacker/cbor/v2"
)

// NewBackendTestShim returns a shim that implements
// psiphon/common/internal/testutils.DSLBackendTestShim. This shim, intended
// only for testing, avoids the import cycle that would result if the shared
// test DSL backend imported common/dsl directly.
func NewBackendTestShim() *backendTestShim {
	return &backendTestShim{}
}

type backendTestShim struct {
}

func (b *backendTestShim) ClientIPHeaderName() string {
	return PsiphonClientIPHeader
}

func (b *backendTestShim) ClientGeoIPDataHeaderName() string {
	return PsiphonClientGeoIPDataHeader
}

func (b *backendTestShim) ClientTunneledHeaderName() string {
	return PsiphonClientTunneledHeader
}

func (b *backendTestShim) HostIDHeaderName() string {
	return PsiphonHostIDHeader
}

func (b *backendTestShim) DiscoverServerEntriesRequestPath() string {
	return RequestPathDiscoverServerEntries
}

func (b *backendTestShim) GetServerEntriesRequestPath() string {
	return RequestPathGetServerEntries
}

func (b *backendTestShim) GetActiveOSLsRequestPath() string {
	return RequestPathGetActiveOSLs
}

func (b *backendTestShim) GetOSLFileSpecsRequestPath() string {
	return RequestPathGetOSLFileSpecs
}

func (b *backendTestShim) UnmarshalDiscoverServerEntriesRequest(
	cborRequest []byte) (

	apiParams protocol.PackedAPIParameters,
	oslKeys [][]byte,
	discoverCount int32,
	retErr error) {

	var request *DiscoverServerEntriesRequest
	err := cbor.Unmarshal(cborRequest, &request)
	if err != nil {
		return nil, nil, 0, errors.Trace(err)
	}

	return request.BaseAPIParameters,
		convertSlice[OSLKey, []byte](request.OSLKeys),
		request.DiscoverCount,
		nil
}

func (b *backendTestShim) MarshalDiscoverServerEntriesResponse(
	versionedServerEntryTags []*struct {
		Tag            []byte
		Version        int32
		PrioritizeDial bool
	}) (

	cborResponse []byte,
	retErr error) {

	response := &DiscoverServerEntriesResponse{
		VersionedServerEntryTags: convertSlice[
			*struct {
				Tag            []byte
				Version        int32
				PrioritizeDial bool
			}, *VersionedServerEntryTag](versionedServerEntryTags),
	}

	cborResponse, err := protocol.CBOREncoding.Marshal(response)
	return cborResponse, errors.Trace(err)
}

func (b *backendTestShim) UnmarshalGetServerEntriesRequest(
	cborRequest []byte) (

	apiParams protocol.PackedAPIParameters,
	serverEntryTags [][]byte,
	retErr error) {

	var request *GetServerEntriesRequest
	err := cbor.Unmarshal(cborRequest, &request)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	return request.BaseAPIParameters,
		convertSlice[ServerEntryTag, []byte](request.ServerEntryTags),
		nil
}

func (b *backendTestShim) MarshalGetServerEntriesResponse(
	sourcedServerEntries []*struct {
		ServerEntryFields protocol.PackedServerEntryFields
		Source            string
	}) (

	cborResponse []byte,
	retErr error) {

	response := &GetServerEntriesResponse{
		SourcedServerEntries: convertSlice[
			*struct {
				ServerEntryFields protocol.PackedServerEntryFields
				Source            string
			}, *SourcedServerEntry](sourcedServerEntries),
	}

	cborResponse, err := protocol.CBOREncoding.Marshal(response)
	return cborResponse, errors.Trace(err)
}

func (b *backendTestShim) UnmarshalGetActiveOSLsRequest(
	cborRequest []byte) (

	apiParams protocol.PackedAPIParameters,
	retErr error) {

	var request *GetActiveOSLsRequest
	err := cbor.Unmarshal(cborRequest, &request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return request.BaseAPIParameters, nil
}

func (b *backendTestShim) MarshalGetActiveOSLsResponse(
	activeOSLIDs [][]byte) (

	cborResponse []byte,
	retErr error) {

	response := &GetActiveOSLsResponse{
		ActiveOSLIDs: convertSlice[[]byte, OSLID](activeOSLIDs),
	}

	cborResponse, err := protocol.CBOREncoding.Marshal(response)
	return cborResponse, errors.Trace(err)
}

func (b *backendTestShim) UnmarshalGetOSLFileSpecsRequest(
	cborRequest []byte) (

	apiParams protocol.PackedAPIParameters,
	oslIDs [][]byte,
	retErr error) {

	var request *GetOSLFileSpecsRequest
	err := cbor.Unmarshal(cborRequest, &request)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	return request.BaseAPIParameters,
		convertSlice[OSLID, []byte](request.OSLIDs),
		nil
}

func (b *backendTestShim) MarshalGetOSLFileSpecsResponse(
	oslFileSpecs [][]byte) (

	cborResponse []byte,
	retErr error) {

	response := &GetOSLFileSpecsResponse{
		OSLFileSpecs: convertSlice[[]byte, OSLFileSpec](oslFileSpecs),
	}

	cborResponse, err := protocol.CBOREncoding.Marshal(response)
	return cborResponse, errors.Trace(err)
}

func convertSlice[A any, B any](s []A) []B {
	if len(s) == 0 {
		return []B{}
	}

	var a A
	var b B
	if unsafe.Sizeof(a) != unsafe.Sizeof(b) {
		panic("incompatible types")
	}

	return *(*[]B)(unsafe.Pointer(&s))
}
