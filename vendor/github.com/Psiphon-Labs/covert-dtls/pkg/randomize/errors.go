package randomize

import (
	"errors"

	"github.com/pion/dtls/v3/pkg/protocol"
)

// Typed errors
var (
	errBufferTooSmall = &protocol.TemporaryError{Err: errors.New("buffer is too small")}                         //nolint:goerr113
	errLengthMismatch = &protocol.InternalError{Err: errors.New("data length and declared length do not match")} //nolint:goerr113
	errCookieTooLong  = &protocol.FatalError{Err: errors.New("cookie must not be longer then 255 bytes")}        //nolint:goerr113
)
