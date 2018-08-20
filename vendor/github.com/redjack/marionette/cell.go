package marionette

import (
	"bytes"
	"encoding/binary"
	"io"
)

const (
	// CellHeaderSize is the number of non-payload bytes used by a cell.
	CellHeaderSize = 25

	// MaxCellLength is the maximum allowed size of a serialized cell.
	MaxCellLength = 32768
)

const (
	// Normal cells carry zero or more bytes in a payload.
	CellTypeNormal = 0x1

	// EOS (end-of-stream) cells mark the end of streams and carry no payload.
	CellTypeEOS = 0x2
)

// Cell represents a single unit of data sent between the client & server.
//
// This cell is associated with a specific stream and the encoder/decoders
// handle ordering based on sequence id.
type Cell struct {
	Type       int    // Record type (normal, end-of-stream)
	Payload    []byte // Data
	Length     int    // Size of marshaled data, if specified.
	StreamID   int    // Associated stream
	SequenceID int    // Record number within stream
	UUID       int    // MAR format identifier
	InstanceID int    // MAR instance identifier
}

// NewCell returns a new instance of Cell.
func NewCell(streamID, sequenceID, length, typ int) *Cell {
	return &Cell{
		Type:       typ,
		SequenceID: sequenceID,
		Length:     length,
		StreamID:   streamID,
	}
}

// Compare returns -1 if c has a lower sequence than other, 1 if c has a higher
// sequence than other, and 0 if both cells have the same sequence.
func (c *Cell) Compare(other *Cell) int {
	if c.SequenceID < other.SequenceID {
		return -1
	} else if c.SequenceID > other.SequenceID {
		return 1
	}
	return 0
}

// Equal returns true if the payload, stream id, sequence, uuid, and instance id are the same.
func (c *Cell) Equal(other *Cell) bool {
	if c == nil && other == nil {
		return true
	} else if (c != nil && other == nil) || (c == nil && other != nil) {
		return false
	}
	return bytes.Equal(c.Payload, other.Payload) &&
		c.StreamID == other.StreamID &&
		c.UUID == other.UUID &&
		c.InstanceID == other.InstanceID &&
		c.SequenceID == other.SequenceID
}

// Size returns the marshaled size of the cell, in bytes.
func (c *Cell) Size() int {
	return CellHeaderSize + len(c.Payload) + c.paddingN()
}

// paddingN returns the length of padding, in bytes, if a length is specified.
// If no length is provided or the length is smaller than Size() then 0 is returned.
func (c *Cell) paddingN() int {
	n := c.Length - len(c.Payload) - CellHeaderSize
	if n < 0 {
		return 0
	}
	return n
}

// MarshalBinary returns a byte slice with a serialized cell.
func (c *Cell) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, c.Size()))
	binary.Write(buf, binary.BigEndian, uint32(c.Size()))
	binary.Write(buf, binary.BigEndian, uint32(len(c.Payload)))
	binary.Write(buf, binary.BigEndian, uint32(c.UUID))
	binary.Write(buf, binary.BigEndian, uint32(c.InstanceID))
	binary.Write(buf, binary.BigEndian, uint32(c.StreamID))
	binary.Write(buf, binary.BigEndian, uint32(c.SequenceID))
	binary.Write(buf, binary.BigEndian, uint8(c.Type))
	buf.Write(c.Payload)
	buf.Write(make([]byte, c.paddingN()))
	assert(buf.Len() == CellHeaderSize+len(c.Payload)+c.paddingN())
	return buf.Bytes(), nil
}

// UnmarshalBinary decodes a serialized cell.
func (c *Cell) UnmarshalBinary(data []byte) (err error) {
	br := bytes.NewReader(data)

	// Read cell size.
	var sz, payloadN, u32 uint32
	if err := binary.Read(br, binary.BigEndian, &sz); err != nil {
		return err
	}
	c.Length = int(sz)

	// Limit the reader to the bytes in the cell (minus the sz field).
	r := io.LimitReader(br, int64(c.Length-4))

	// Read payload size.
	if err := binary.Read(r, binary.BigEndian, &payloadN); err != nil {
		return err
	}

	// Read model uuid.
	if err := binary.Read(r, binary.BigEndian, &u32); err != nil {
		return err
	}
	c.UUID = int(u32)

	// Read model instance id.
	if err := binary.Read(r, binary.BigEndian, &u32); err != nil {
		return err
	}
	c.InstanceID = int(u32)

	// Read stream id.
	if err := binary.Read(r, binary.BigEndian, &u32); err != nil {
		return err
	}
	c.StreamID = int(u32)

	// Read sequence id.
	if err := binary.Read(r, binary.BigEndian, &u32); err != nil {
		return err
	}
	c.SequenceID = int(u32)

	// Read cell type.
	var u8 uint8
	if err := binary.Read(r, binary.BigEndian, &u8); err != nil {
		return err
	}
	c.Type = int(u8)

	// Read payload.
	if payloadN > 0 {
		c.Payload = make([]byte, payloadN)
		if _, err := r.Read(c.Payload); err != nil {
			return err
		}
		return err
	} else {
		c.Payload = nil
	}

	return nil
}
