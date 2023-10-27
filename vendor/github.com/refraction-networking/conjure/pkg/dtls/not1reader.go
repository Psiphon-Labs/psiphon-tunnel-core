package dtls

import (
	"io"
)

type Not1Reader struct {
	r io.Reader
}

func (n1r *Not1Reader) Read(p []byte) (n int, err error) {

	if len(p) == 1 {
		// err = io.EOF
		return 1, nil
	}

	return n1r.r.Read(p)
}
