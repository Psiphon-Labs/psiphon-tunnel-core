package utils

import (
	"errors"

	"github.com/pion/dtls/v3/pkg/protocol"
)

// Typed errors
var (
	errBufferTooSmall = &protocol.TemporaryError{Err: errors.New("buffer is too small")}                         //nolint:goerr113
	errLengthMismatch = &protocol.InternalError{Err: errors.New("data length and declared length do not match")} //nolint:goerr113
)
