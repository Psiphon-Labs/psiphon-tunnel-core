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

package main

/*
#include <stdlib.h>
#include <stdint.h>

// For descriptions of fields, see below.
// Additional information can also be found in the Parameters structure in clientlib.go.
struct Parameters {
	size_t sizeofStruct; // Must be set to sizeof(Parameters); helps with ABI compatibiity
	char *dataRootDirectory;
	char *clientPlatform;
	char *networkID;
	int32_t *establishTunnelTimeoutSeconds;
};
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"unsafe"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/ClientLibrary/clientlib"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

/*
If/when new fields are added to the C Parameters struct, we can use this code to ensure
ABI compatibility. We'll take these steps:
1. Copy the old struct into a new `ParametersV1`. The new struct will be `Parameters`.
2. Uncomment the code below. It will not compile (link, specifically) if the size of
   `Parameters` is the same as the size of `ParametersV1`.
   - If the compile fails, padding may need to be added to `Parameters` to force it to be
     a different size than `ParametersV1`.
3. In `Start`, we'll check the value of `sizeofStruct` to determine which version of
   `Parameters` the caller is using, and behave according.
4. Do similar kinds of things for V2, V3, etc.
*/
/*
func nonexistentFunction()
func init() {
	if C.sizeof_struct_Parameters == C.sizeof_struct_ParametersV1 {
		// There is only an attempt to link this nonexistent function if the struct sizes
		// are the same. So they must not be.
		nonexistentFunction()
	}
}
*/

type startResultCode int

const (
	startResultCodeSuccess    startResultCode = 0
	startResultCodeTimeout    startResultCode = 1
	startResultCodeOtherError startResultCode = 2
)

type startResult struct {
	Code           startResultCode
	ConnectTimeMS  int64  `json:",omitempty"`
	Error          string `json:",omitempty"`
	HTTPProxyPort  int    `json:",omitempty"`
	SOCKSProxyPort int    `json:",omitempty"`
}

var tunnel *clientlib.PsiphonTunnel

// Memory managed by PsiphonTunnel which is allocated in Start and freed in Stop
var managedStartResult *C.char

// ******************************* WARNING ********************************
// The underlying memory referenced by the return value of Start is managed
// by PsiphonTunnel and attempting to free it explicitly will cause the
// program to crash. This memory is freed once Stop is called, or if Start
// is called again.
// ************************************************************************
//
// Start starts the controller and returns once one of the following has occured:
// an active tunnel has been established, the timeout has elapsed before an active tunnel
// could be established, or an error has occured.
//
// Start returns a startResult object serialized as a JSON string in the form of a
// null-terminated buffer of C chars.
// Start will return,
// On success:
//
//	{
//	  "Code": 0,
//	  "ConnectTimeMS": <milliseconds to establish tunnel>,
//	  "HTTPProxyPort": <http proxy port number>,
//	  "SOCKSProxyPort": <socks proxy port number>
//	}
//
// On timeout:
//
//	{
//	  "Code": 1,
//	  "Error": <error message>
//	}
//
// On other error:
//
//	{
//	  "Code": 2,
//	  "Error": <error message>
//	}
//
// Parameters.clientPlatform should be of the form OS_OSVersion_BundleIdentifier where
// both the OSVersion and BundleIdentifier fields are optional. If clientPlatform is set
// to an empty string the "ClientPlatform" field in the provided JSON config will be
// used instead.
//
// Provided below are links to platform specific code which can be used to find some of the above fields:
//
//	Android:
//	  - OSVersion: https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/3d344194d21b250e0f18ededa4b4459a373b0690/MobileLibrary/Android/PsiphonTunnel/PsiphonTunnel.java#L573
//	  - BundleIdentifier: https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/3d344194d21b250e0f18ededa4b4459a373b0690/MobileLibrary/Android/PsiphonTunnel/PsiphonTunnel.java#L575
//	iOS:
//	  - OSVersion: https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/3d344194d21b250e0f18ededa4b4459a373b0690/MobileLibrary/iOS/PsiphonTunnel/PsiphonTunnel/PsiphonTunnel.m#L612
//	  - BundleIdentifier: https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/3d344194d21b250e0f18ededa4b4459a373b0690/MobileLibrary/iOS/PsiphonTunnel/PsiphonTunnel/PsiphonTunnel.m#L622
//
// Some examples of valid client platform strings are:
//
//	"Android_4.2.2_com.example.exampleApp"
//	"iOS_11.4_com.example.exampleApp"
//	"Windows"
//
// Parameters.networkID must be a non-empty string and follow the format specified by:
// https://godoc.org/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon#NetworkIDGetter.
// Provided below are links to platform specific code which can be used to generate
// valid network identifier strings:
//
//	Android:
//	  - https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/3d344194d21b250e0f18ededa4b4459a373b0690/MobileLibrary/Android/PsiphonTunnel/PsiphonTunnel.java#L371
//	iOS:
//	  - https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/3d344194d21b250e0f18ededa4b4459a373b0690/MobileLibrary/iOS/PsiphonTunnel/PsiphonTunnel/PsiphonTunnel.m#L1105
//
// Parameters.establishTunnelTimeoutSeconds specifies a time limit after which to stop
// attempting to connect and return an error if an active tunnel has not been established.
// A timeout of 0 will result in no timeout condition and the controller will attempt to
// establish an active tunnel indefinitely (or until PsiphonTunnelStop is called).
// Timeout values >= 0 override the optional `EstablishTunnelTimeoutSeconds` config field;
// null causes the config value to be used.
//
//export PsiphonTunnelStart
func PsiphonTunnelStart(cConfigJSON, cEmbeddedServerEntryList *C.char, cParams *C.struct_Parameters) *C.char {
	// Stop any active tunnels
	PsiphonTunnelStop()

	if cConfigJSON == nil {
		err := errors.Tracef("configJSON is required")
		managedStartResult = startErrorJSON(err)
		return managedStartResult
	}

	if cParams == nil {
		err := errors.Tracef("params is required")
		managedStartResult = startErrorJSON(err)
		return managedStartResult
	}

	if cParams.sizeofStruct != C.sizeof_struct_Parameters {
		err := errors.Tracef("sizeofStruct does not match sizeof(Parameters)")
		managedStartResult = startErrorJSON(err)
		return managedStartResult
	}

	// NOTE: all arguments which may be referenced once Start returns must be copied onto
	// the Go heap to ensure that they don't disappear later on and cause Go to crash.
	configJSON := []byte(C.GoString(cConfigJSON))
	embeddedServerEntryList := C.GoString(cEmbeddedServerEntryList)

	params := clientlib.Parameters{}
	if cParams.dataRootDirectory != nil {
		v := C.GoString(cParams.dataRootDirectory)
		params.DataRootDirectory = &v
	}
	if cParams.clientPlatform != nil {
		v := C.GoString(cParams.clientPlatform)
		params.ClientPlatform = &v
	}
	if cParams.networkID != nil {
		v := C.GoString(cParams.networkID)
		params.NetworkID = &v
	}
	if cParams.establishTunnelTimeoutSeconds != nil {
		v := int(*cParams.establishTunnelTimeoutSeconds)
		params.EstablishTunnelTimeoutSeconds = &v
	}

	// As Client Library doesn't currently implement callbacks, diagnostic
	// notices aren't relayed to the client application. Set
	// EmitDiagnosticNoticesToFiles to ensure the rotating diagnostic log file
	// facility is used when EmitDiagnosticNotices is specified in the config.
	params.EmitDiagnosticNoticesToFiles = true

	startTime := time.Now()

	// Start the tunnel connection
	var err error
	tunnel, err = clientlib.StartTunnel(
		context.Background(), configJSON, embeddedServerEntryList, params, nil, nil)

	if err != nil {
		if err == clientlib.ErrTimeout {
			managedStartResult = marshalStartResult(startResult{
				Code:  startResultCodeTimeout,
				Error: fmt.Sprintf("Timeout occurred before Psiphon connected: %s", err.Error()),
			})
		} else {
			managedStartResult = marshalStartResult(startResult{
				Code:  startResultCodeOtherError,
				Error: err.Error(),
			})
		}
		return managedStartResult
	}

	// Success
	managedStartResult = marshalStartResult(startResult{
		Code:           startResultCodeSuccess,
		ConnectTimeMS:  int64(time.Since(startTime) / time.Millisecond),
		HTTPProxyPort:  tunnel.HTTPProxyPort,
		SOCKSProxyPort: tunnel.SOCKSProxyPort,
	})
	return managedStartResult
}

// Stop stops the controller if it is running and waits for it to clean up and exit.
//
// Stop should always be called after a successful call to Start to ensure the
// controller is not left running and memory is released.
// It is safe to call this function when the tunnel is not running.
//
//export PsiphonTunnelStop
func PsiphonTunnelStop() {
	freeManagedStartResult()
	if tunnel != nil {
		tunnel.Stop()
	}
}

// marshalStartResult serializes a startResult object as a JSON string in the form
// of a null-terminated buffer of C chars.
func marshalStartResult(result startResult) *C.char {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		err = errors.TraceMsg(err, "json.Marshal failed")
		// Fail back to manually constructing the JSON
		return C.CString(fmt.Sprintf("{\"Code\":%d, \"Error\": \"%s\"}",
			startResultCodeOtherError, err.Error()))
	}

	return C.CString(string(resultJSON))
}

// startErrorJSON returns a startResult object serialized as a JSON string in the form of
// a null-terminated buffer of C chars. The object's return result code will be set to
// startResultCodeOtherError (2) and its error string set to the error string of the
// provided error.
//
// The JSON will be in the form of:
//
//	{
//	  "Code": 2,
//	  "Error": <error message>
//	}
func startErrorJSON(err error) *C.char {
	var result startResult
	result.Code = startResultCodeOtherError
	result.Error = err.Error()

	return marshalStartResult(result)
}

// freeManagedStartResult frees the memory on the heap pointed to by managedStartResult.
func freeManagedStartResult() {
	if managedStartResult != nil {
		managedMemory := unsafe.Pointer(managedStartResult)
		if managedMemory != nil {
			C.free(managedMemory)
		}
		managedStartResult = nil
	}
}

// main is a stub required by cgo.
func main() {}
