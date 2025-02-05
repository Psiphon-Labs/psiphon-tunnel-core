// Copyright 2019 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package net

type ConnectionError struct {
	// TODO: create status enums and move to metrics.go
	Status  string
	Message string
	Cause   error
}

func NewConnectionError(status, message string, cause error) *ConnectionError {
	return &ConnectionError{Status: status, Message: message, Cause: cause}
}

func (e *ConnectionError) Error() string {
	if e == nil {
		return "<nil>"
	}
	msg := e.Message
	if len(e.Status) > 0 {
		msg += " [" + e.Status + "]"
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *ConnectionError) Unwrap() error {
	return e.Cause
}

var _ error = (*ConnectionError)(nil)
