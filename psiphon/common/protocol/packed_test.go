/*
 * Copyright (c) 2023, Psiphon Inc.
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

package protocol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/accesscontrol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func TestPackedAPIParameters(t *testing.T) {

	params := make(common.APIParameters)

	for name, spec := range packedAPIParametersNameToSpec {
		params[name] = makeTestPackValue(t, spec)
	}

	packedParams, err := EncodePackedAPIParameters(params)
	if err != nil {
		t.Fatalf("EncodePackedAPIParameters failed: %v", err)
	}

	unpackedParams, err := DecodePackedAPIParameters(packedParams)
	if err != nil {
		t.Fatalf("DecodePackedAPIParameters failed: %v", err)
	}

	checkTestPackValues(
		t, packedAPIParametersNameToSpec, params, unpackedParams)
}

func TestPackedServerEntry(t *testing.T) {

	fields := make(ServerEntryFields)

	for name, spec := range packedServerEntryFieldsNameToSpec {
		fields[name] = makeTestPackValue(t, spec)
	}
	unrecognized := "unrecognized_field_name"
	fields[unrecognized] = prng.HexString(prng.Range(1, 1000))

	packedFields, err := EncodePackedServerEntryFields(fields)
	if err != nil {
		t.Fatalf("EncodePackedServerEntryFields failed: %v", err)
	}

	unpackedFields, err := DecodePackedServerEntryFields(packedFields)
	if err != nil {
		t.Fatalf("DecodePackedServerEntryFields failed: %v", err)
	}

	checkTestPackValues(
		t, packedServerEntryFieldsNameToSpec, fields, unpackedFields)

	if !reflect.DeepEqual(fields[unrecognized], unpackedFields[unrecognized]) {
		t.Errorf("decoded value %s not equal: %T %+v != %T %+v",
			unrecognized,
			fields[unrecognized], fields[unrecognized],
			unpackedFields[unrecognized], unpackedFields[unrecognized])
	}
}

func makeTestPackValue(t *testing.T, spec packSpec) interface{} {
	switch spec.converter {
	case nil:
		return prng.HexString(prng.Range(1, 1000))
	case intConverter:
		return fmt.Sprintf("%d", prng.Intn(1>>32))
	case floatConverter:
		return fmt.Sprintf("%f", float64(prng.Intn(1>>32)))
	case lowerHexConverter:
		return prng.HexString(prng.Range(1, 1000))
	case upperHexConverter:
		return strings.ToUpper(prng.HexString((prng.Range(1, 1000))))
	case base64Converter:
		return base64.StdEncoding.EncodeToString(prng.Bytes(prng.Range(1, 1000)))
	case unpaddedBase64Converter:
		return base64.RawStdEncoding.EncodeToString(prng.Bytes(prng.Range(1, 1000)))
	case authorizationsConverter:
		signingKey, _, err0 := accesscontrol.NewKeyPair("test-access-type")
		auth1, _, err1 := accesscontrol.IssueAuthorization(signingKey, []byte("1"), time.Now().Add(1*time.Second))
		auth2, _, err2 := accesscontrol.IssueAuthorization(signingKey, []byte("2"), time.Now().Add(1*time.Second))
		if err0 != nil || err1 != nil || err2 != nil {
			t.Fatalf("accesscontrol.NewKeyPair/IssueAuthorization failed")
		}
		return []string{auth1, auth2}
	case rawJSONConverter:
		return []byte(fmt.Sprintf(`{"A":%d, "B":%d}`, prng.Intn(1>>32), prng.Intn(1>>32)))
	case compatibleJSONMapConverter:
		return []any{map[any]any{"a": 1, "b": 2}, map[any]any{"a": 3, "b": 4}}
	}
	t.Fatalf("unexpected converter")
	return nil
}

func checkTestPackValues(
	t *testing.T,
	specs map[string]packSpec,
	originalValues map[string]interface{},
	unpackedValues map[string]interface{}) {

	for name, spec := range specs {
		originalValue := originalValues[name]
		unpackedValue := unpackedValues[name]
		if spec.converter == rawJSONConverter {

			// Special case: for rawJSONConverter, the input is bytes while
			// the output is unmarshaled JSON.
			var unmarshaledJSON map[string]interface{}
			_ = json.Unmarshal(originalValue.([]byte), &unmarshaledJSON)
			originalValue = unmarshaledJSON

		} else if spec.converter == compatibleJSONMapConverter {

			// Special case: for compatibleJSONMapConverter, reverse the
			// conversion to produce the original value with the same type.
			unpackedSlice, ok := unpackedValue.([]map[string]interface{})
			if !ok {
				t.Errorf("expected []map[string]interface {} type")
				return
			}
			entries := make([]interface{}, len(unpackedSlice))
			for i, unpackedEntry := range unpackedSlice {
				entry := make(map[interface{}]interface{})
				for key, value := range unpackedEntry {
					entry[key] = value
				}
				entries[i] = entry
			}
			unpackedValue = entries
		}
		if !reflect.DeepEqual(originalValue, unpackedValue) {
			t.Errorf("decoded value %s not equal: %T %+v != %T %+v",
				name, originalValue, originalValue, unpackedValue, unpackedValue)
		}
	}
}
