package obfuscator

import (
	"bytes"
	"io"
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

type SkipReader struct {
	net.Conn
	offset int // buf offset for next Read
	end    int // buf end index for next Read
	buf    []byte
}

func WrapConnWithSkipReader(conn net.Conn) net.Conn {
	return &SkipReader{
		Conn:   conn,
		offset: 0,
		end:    0,
		buf:    nil,
	}
}

func (sr *SkipReader) Read(b []byte) (int, error) {

	// read buffered bytes first
	if sr.offset < sr.end {
		n := copy(b, sr.buf[sr.offset:sr.end])
		if n == 0 {
			// should never happen if len(b) > 0
			return 0, errors.TraceNew("read failed")
		}

		sr.offset += n

		// clear resources if all buffered bytes are read
		if sr.offset == sr.end {
			sr.offset = 0
			sr.end = 0
			sr.buf = nil
		}

		return n, nil
	}

	return sr.Conn.Read(b)
}

// SkipUpToToken reads from the underlying conn initially len(token) bytes,
// and then readSize bytes at a time up to maxSearchSize until token is found,
// or error. If the token is found, stream is rewound to end of the token.
//
// Note that maxSearchSize is not a strict limit on the total number of bytes read.
func (sr *SkipReader) SkipUpToToken(
	token []byte, readSize, maxSearchSize int) error {

	if len(token) == 0 {
		return nil
	}
	if readSize < 1 {
		return errors.TraceNew("readSize too small")
	}
	if maxSearchSize < readSize {
		return errors.TraceNew("maxSearchSize too small")
	}

	sr.offset = 0
	sr.end = 0
	sr.buf = make([]byte, readSize+len(token))

	// Reads at least len(token) bytes.
	nTotal, err := io.ReadFull(sr.Conn, sr.buf[:len(token)])
	if err == io.ErrUnexpectedEOF {
		return errors.TraceNew("token not found")
	}
	if err != nil {
		return err
	}

	if bytes.Equal(sr.buf[:len(token)], token) {
		return nil
	}

	for nTotal < maxSearchSize {

		// The underlying conn is read into buf[len(token):].
		// buf[:len(token)] stores bytes from the previous read.
		n, err := sr.Conn.Read(sr.buf[len(token):])
		if err != nil && err != io.EOF {
			return err
		}

		if idx := bytes.Index(sr.buf[:n+len(token)], token); idx != -1 {
			// Found match, sets offset and end for next Read to start after the token.
			sr.offset = idx + len(token)
			sr.end = n + len(token)
			return err
		}

		if err == io.EOF {
			// Reached the end of stream, token not found.
			return errors.TraceNew("token not found")
		}

		// Copies last len(token) bytes to the beginning of the buffer.
		copy(sr.buf, sr.buf[n:n+len(token)])
		nTotal += n
	}

	return errors.TraceNew("exceeded max search size")
}
