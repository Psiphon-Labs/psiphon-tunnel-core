package utils

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

const (
	keyShareHeaderSize                      = 6
	KeyGroupP256Value                       = 23
	KeyGroupX25519Value                     = 29
	KeyShareTypeValue   extension.TypeValue = 51
)

var (
	errKeyLength            = errors.New("generated key length does not match")
	errRandomKey            = errors.New("error while generating random key")
	errInvalidExtensionType = errors.New("invalid extension type")
)

type KeyShareEntry struct {
	Group     uint16
	KeyLength uint16
	Key       []byte
}

type KeyShare struct {
	KeyShareEntries []KeyShareEntry
}

func (k *KeyShare) TypeValue() extension.TypeValue {
	return KeyShareTypeValue
}

// Marshal with fresh random keys
func (k *KeyShare) Marshal() ([]byte, error) {
	var tmp []byte
	for _, entry := range k.KeyShareEntries {
		out := []byte{0x00, 0x00}
		binary.BigEndian.PutUint16(out, uint16(entry.Group))
		tmp = append(tmp, out...)
		out = []byte{0x00, 0x00}
		binary.BigEndian.PutUint16(out, uint16(entry.KeyLength))
		tmp = append(tmp, out...)
		switch entry.Group {
		case uint16(KeyGroupX25519Value):
			key, err := GenerateRandomX25519PublicKey()
			if err != nil {
				return []byte{}, err
			}
			if len(key.Bytes()) != int(entry.KeyLength) {
				return []byte{}, errKeyLength
			}
			tmp = append(tmp, key.Bytes()...)
		case uint16(KeyGroupP256Value):
			key, err := GenerateRandomP256PublicKey()
			if err != nil {
				return []byte{}, err
			}
			if len(key.Bytes()) != int(entry.KeyLength) {
				return []byte{}, errKeyLength
			}
			tmp = append(tmp, key.Bytes()...)
		default:
			key := make([]byte, entry.KeyLength)
			_, err := rand.Read(key)
			if err != nil {
				return []byte{}, errRandomKey
			}
			tmp = append(tmp, key...)
		}
	}

	var header []byte
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out, uint16(k.TypeValue()))
	header = append(header, out...)

	out = []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out, uint16(len(tmp)+2))
	header = append(header, out...)

	out = []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out, uint16(len(tmp)))
	header = append(header, out...)

	out = append(header, tmp...)
	return out, nil
}

func (k *KeyShare) Unmarshal(data []byte) error {
	if len(data) <= keyShareHeaderSize {
		return errBufferTooSmall
	} else if extension.TypeValue(binary.BigEndian.Uint16(data)) != k.TypeValue() {
		return errInvalidExtensionType
	}

	length := int(binary.BigEndian.Uint16(data[2:])) + 4 // offset = 2 byte type + 2 byte length
	// [Psiphon] Fix boundary check: compare against len(data) instead of
	// len(data[2:]), and use > instead of >= so the extension whose data
	// exactly consumes all remaining bytes is not rejected.
	if length > len(data) {
		return errLengthMismatch
	}
	data = data[:length]

	currOff := keyShareHeaderSize
	for currOff < len(data) {
		group := binary.BigEndian.Uint16(data[currOff:])
		currOff += 2
		if currOff >= len(data) {
			return errLengthMismatch
		}
		keyLength := binary.BigEndian.Uint16(data[currOff:])
		keyShareEntry := KeyShareEntry{Group: group, KeyLength: keyLength}
		k.KeyShareEntries = append(k.KeyShareEntries, keyShareEntry)
		currOff += 2 + int(keyLength)
	}
	return nil
}
