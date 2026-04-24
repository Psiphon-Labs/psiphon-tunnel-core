package mimicry

import (
	"errors"

	"github.com/pion/dtls/v3/pkg/protocol"
)

// Typed errors.
var (
	errCookieTooLong = &protocol.FatalError{
		Err: errors.New("cookie must not be longer then 255 bytes"), //nolint:err113
	}
	errBufferTooSmall = &protocol.TemporaryError{
		Err: errors.New("buffer is too small"), //nolint:err113
	}
	errLengthMismatch = &protocol.InternalError{
		Err: errors.New("data length and declared length do not match"), //nolint:err113
	}
	errNoFingerprints  = errors.New("no fingerprints available")
	errHexstringDecode = errors.New("mimicry: failed to decode mimicry hexstring")
)
