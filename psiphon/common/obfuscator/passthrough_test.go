/*
 * Copyright (c) 2020, Psiphon Inc.
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

package obfuscator

import (
	"bytes"
	"testing"
)

func TestTLSPassthrough(t *testing.T) {

	correctMasterKey := "correct-master-key"
	incorrectMasterKey := "incorrect-master-key"

	passthroughKey, err := DeriveTLSPassthroughKey(correctMasterKey)
	if err != nil {
		t.Fatalf("DeriveTLSPassthroughKey failed: %s", err)
	}

	validMessage, err := MakeTLSPassthroughMessage(correctMasterKey)
	if err != nil {
		t.Fatalf("MakeTLSPassthroughMessage failed: %s", err)
	}

	if !VerifyTLSPassthroughMessage(passthroughKey, validMessage) {
		t.Fatalf("unexpected invalid passthrough messages")
	}

	anotherValidMessage, err := MakeTLSPassthroughMessage(correctMasterKey)
	if err != nil {
		t.Fatalf("MakeTLSPassthroughMessage failed: %s", err)
	}

	if bytes.Equal(validMessage, anotherValidMessage) {
		t.Fatalf("unexpected identical passthrough messages")
	}

	invalidMessage, err := MakeTLSPassthroughMessage(incorrectMasterKey)
	if err != nil {
		t.Fatalf("MakeTLSPassthroughMessage failed: %s", err)
	}

	if VerifyTLSPassthroughMessage(passthroughKey, invalidMessage) {
		t.Fatalf("unexpected valid passthrough messages")
	}
}
