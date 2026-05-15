// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"

	"github.com/pion/dtls/v3/pkg/protocol"
)

var (
	// ErrALPNInvalidFormat is raised when the ALPN format is invalid.
	ErrALPNInvalidFormat = &protocol.FatalError{
		Err: errors.New("invalid alpn format"), //nolint:err113
	}
	errALPNNoAppProto = &protocol.FatalError{
		Err: errors.New("no application protocol"), //nolint:err113
	}
	errBufferTooSmall = &protocol.TemporaryError{
		Err: errors.New("buffer is too small"), //nolint:err113
	}
	errInvalidExtensionType = &protocol.FatalError{
		Err: errors.New("invalid extension type"), //nolint:err113
	}
	errInvalidSNIFormat = &protocol.FatalError{
		Err: errors.New("invalid server name format"), //nolint:err113
	}
	errInvalidCIDFormat = &protocol.FatalError{
		Err: errors.New("invalid connection ID format"), //nolint:err113
	}
	errLengthMismatch = &protocol.InternalError{
		Err: errors.New("data length and declared length do not match"), //nolint:err113
	}
	errMasterKeyIdentifierTooLarge = &protocol.FatalError{
		Err: errors.New("master key identifier is over 255 bytes"), //nolint:err113
	}
	errPreSharedKeyFormat = &protocol.FatalError{
		Err: errors.New("invalid Pre-Shared Key extension format"), //nolint:err113
	}
	errPskKeyExchangeModesFormat = &protocol.FatalError{
		Err: errors.New("invalid Pre-Shared Key Exchange Modes extension format"), //nolint:err113
	}
	errNoPskKeyExchangeMode = &protocol.InternalError{
		Err: errors.New("no mode set for the Pre-Shared Key Exchange Modes extension"), //nolint:err113
	}
	errCookieExtFormat = &protocol.FatalError{
		Err: errors.New("invalid cookie format"), //nolint:err113
	}
	errInvalidKeyShareFormat = &protocol.FatalError{
		Err: errors.New("invalid key_share format"), //nolint:err113
	}
	errDuplicateKeyShare = &protocol.FatalError{
		Err: errors.New("duplicate key_share group"), //nolint:err113
	}
	errInvalidSupportedVersionsFormat = &protocol.FatalError{
		Err: errors.New("invalid supported_versions format"), //nolint:err113
	}
	errInvalidDTLSVersion = &protocol.InternalError{
		Err: errors.New("invalid dtls version was provided"), //nolint:err113
	}
)
