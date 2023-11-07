package msgformat

import (
	"encoding/binary"
	"errors"
)

// Add length prefix to message
func AddRequestFormat(p []byte) ([]byte, error) {
	length := uint8(len(p))
	prefixed := append([]byte{length}, p...)
	return prefixed, nil
}

// Remove the length prefix
func RemoveRequestFormat(p []byte) ([]byte, error) {
	if len(p) < 1 {
		return nil, errors.New("invalid message length")
	}
	length := int(uint8(p[0]))
	if 1+length > len(p) {
		return nil, errors.New("invalid message length")
	}
	return p[1 : 1+length], nil
}

// Add length prefix to response, using uint16 instad of uint8 for larger payload
func AddResponseFormat(p []byte) ([]byte, error) {
	length := uint16(len(p))
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, length)
	prefixed := append(b, p...)
	return prefixed, nil
}

// Remove the length prefix
func RemoveResponseFormat(p []byte) ([]byte, error) {
	if len(p) < 2 {
		return nil, errors.New("invalid message length")
	}
	length := int(binary.BigEndian.Uint16(p[0:2]))
	if 2+length > len(p) {
		return nil, errors.New("invalid message length")
	}
	return p[2 : 2+length], nil
}
