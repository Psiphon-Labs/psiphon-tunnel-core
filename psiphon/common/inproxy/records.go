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

package inproxy

import (
	"encoding/binary"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/fxamacker/cbor/v2"
)

// Records are CBOR-encoded data with a preamble, or prefix, indicating the
// encoding schema version, data type, and data length. Records include
// session messages, as well as API requests and responses which are session
// message payloads.

const (
	recordVersion = 1

	recordTypeFirst                          = 1
	recordTypeSessionPacket                  = 1
	recordTypeSessionRoundTrip               = 2
	recordTypeAPIProxyAnnounceRequest        = 3
	recordTypeAPIProxyAnnounceResponse       = 4
	recordTypeAPIProxyAnswerRequest          = 5
	recordTypeAPIProxyAnswerResponse         = 6
	recordTypeAPIClientOfferRequest          = 7
	recordTypeAPIClientOfferResponse         = 8
	recordTypeAPIClientRelayedPacketRequest  = 9
	recordTypeAPIClientRelayedPacketResponse = 10
	recordTypeAPIBrokerServerReport          = 11
	recordTypeAPIServerProxyQualityRequest   = 12
	recordTypeAPIServerProxyQualityResponse  = 13
	recordTypeAPIClientDSLRequest            = 14
	recordTypeAPIClientDSLResponse           = 15
	recordTypeLast                           = 15
)

func marshalRecord(record interface{}, recordType int) ([]byte, error) {
	payload, err := protocol.CBOREncoding.Marshal(record)
	if err != nil {
		return nil, errors.Trace(err)
	}
	payload, err = addRecordPreamble(recordType, payload)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return payload, nil
}

func unmarshalRecord(expectedRecordType int, payload []byte, record interface{}) error {
	payload, err := readRecordPreamble(expectedRecordType, payload)
	if err != nil {
		return errors.Trace(err)
	}
	err = cbor.Unmarshal(payload, record)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

// addRecordPreamble prepends a record preamble to the given record data
// buffer. The input recordType specifies the type to encode; a version
// number identifying the current encoding schema is supplied automatically.
//
// To avoid allocations, addRecordPreamble modifies the input record buffer;
// use like record = append(record, ...).
func addRecordPreamble(
	recordType int, record []byte) ([]byte, error) {

	if recordVersion < 0 || recordVersion > 0xff {
		return nil, errors.TraceNew("invalid record preamble version")
	}

	if recordType < 0 || recordType > 0xff {
		return nil, errors.TraceNew("invalid record preamble type")
	}

	if len(record) > 0xffff {
		return nil, errors.TraceNew("invalid record length")
	}

	// The preamble:
	// [ 1 byte version ][ 1 byte type ][ varint record data length ][ ...record data ... ]

	var preamble [2 + binary.MaxVarintLen64]byte
	preamble[0] = byte(recordVersion)
	preamble[1] = byte(recordType)
	preambleLen := 2 + binary.PutUvarint(preamble[2:], uint64(len(record)))

	// Attempt to use the input buffer, which will avoid an allocation if it
	// has sufficient capacity.
	record = append(record, preamble[:preambleLen]...)
	copy(record[preambleLen:], record[:len(record)-preambleLen])
	copy(record[0:preambleLen], preamble[:preambleLen])

	return record, nil
}

// peekRecordPreambleType returns the record type of the record data payload,
// or an error if the preamble is invalid.
func peekRecordPreambleType(payload []byte) (int, error) {

	if len(payload) < 2 {
		return -1, errors.TraceNew("invalid record preamble length")
	}

	if int(payload[0]) != recordVersion {
		return -1, errors.TraceNew("invalid record preamble version")
	}

	recordType := int(payload[1])

	if recordType < recordTypeFirst || recordType > recordTypeLast {
		return -1, errors.Tracef("invalid record preamble type: %d %x", recordType, payload)
	}

	return recordType, nil
}

// readRecordPreamble consumes the record preamble from the given record data
// payload and returns the remaining record. The record type must match
// expectedRecordType and the version must match a known encoding schema
// version.
//
// To avoid allocations, readRecordPreamble returns a slice of the
// input record buffer; use like record = record[n:].
func readRecordPreamble(expectedRecordType int, payload []byte) ([]byte, error) {

	if len(payload) < 2 {
		return nil, errors.TraceNew("invalid record preamble length")
	}

	if int(payload[0]) != recordVersion {
		return nil, errors.TraceNew("invalid record preamble version")
	}

	if int(payload[1]) != expectedRecordType {
		return nil, errors.Tracef("unexpected record preamble type")
	}

	recordDataLength, n := binary.Uvarint(payload[2:])
	if (recordDataLength == 0 && n <= 0) || 2+n > len(payload) {
		return nil, errors.Tracef("invalid record preamble data length")
	}

	record := payload[2+n:]

	// In the future, the data length field may be used to implement framing
	// for a stream of records. For now, this check is simply a sanity check.
	if len(record) != int(recordDataLength) {
		return nil, errors.TraceNew("unexpected record preamble data length")
	}

	return record, nil
}
