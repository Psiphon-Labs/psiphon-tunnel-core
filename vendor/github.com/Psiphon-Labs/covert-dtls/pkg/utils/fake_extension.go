package utils

import (
	"encoding/binary"

	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

type FakeExt struct {
	FakeTypeValue extension.TypeValue
	Bytes         []byte
}

func (f *FakeExt) TypeValue() extension.TypeValue {
	return f.FakeTypeValue
}

func (f *FakeExt) Marshal() ([]byte, error) {
	return f.Bytes, nil
}

func (f *FakeExt) Unmarshal(data []byte) error {
	if len(data) < 4 {
		return errBufferTooSmall
	}
	f.FakeTypeValue = extension.TypeValue(binary.BigEndian.Uint16(data))

	length := int(binary.BigEndian.Uint16(data[2:])) + 4 // offset = 2 byte type + 2 byte length
	// [Psiphon] Fix boundary check: compare against len(data) instead of
	// len(data[2:]), and use > instead of >= so the last extension in a
	// buffer (where length exactly equals remaining data) is not rejected.
	if length > len(data) {
		return errLengthMismatch
	}
	data = data[:length]

	f.Bytes = data
	return nil
}
