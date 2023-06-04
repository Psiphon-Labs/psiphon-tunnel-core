// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

var errExample = errors.New("an example error")

func TestErrorUnwrap(t *testing.T) {
	cases := []struct {
		err          error
		errUnwrapped []error
	}{
		{
			&FatalError{Err: errExample},
			[]error{errExample},
		},
		{
			&TemporaryError{Err: errExample},
			[]error{errExample},
		},
		{
			&InternalError{Err: errExample},
			[]error{errExample},
		},
		{
			&TimeoutError{Err: errExample},
			[]error{errExample},
		},
		{
			&HandshakeError{Err: errExample},
			[]error{errExample},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(fmt.Sprintf("%T", c.err), func(t *testing.T) {
			err := c.err
			for _, unwrapped := range c.errUnwrapped {
				e := errors.Unwrap(err)
				if !errors.Is(e, unwrapped) {
					t.Errorf("Unwrapped error is expected to be '%v', got '%v'", unwrapped, e)
				}
			}
		})
	}
}

func TestErrorNetError(t *testing.T) {
	cases := []struct {
		err                error
		str                string
		timeout, temporary bool
	}{
		{&FatalError{Err: errExample}, "dtls fatal: an example error", false, false},
		{&TemporaryError{Err: errExample}, "dtls temporary: an example error", false, true},
		{&InternalError{Err: errExample}, "dtls internal: an example error", false, false},
		{&TimeoutError{Err: errExample}, "dtls timeout: an example error", true, true},
		{&HandshakeError{Err: errExample}, "handshake error: an example error", false, false},
		{&HandshakeError{Err: &TimeoutError{Err: errExample}}, "handshake error: dtls timeout: an example error", true, true},
	}
	for _, c := range cases {
		c := c
		t.Run(fmt.Sprintf("%T", c.err), func(t *testing.T) {
			var ne net.Error
			if !errors.As(c.err, &ne) {
				t.Fatalf("%T doesn't implement net.Error", c.err)
			}
			if ne.Timeout() != c.timeout {
				t.Errorf("%T.Timeout() should be %v", c.err, c.timeout)
			}
			if ne.Temporary() != c.temporary { //nolint:staticcheck
				t.Errorf("%T.Temporary() should be %v", c.err, c.temporary)
			}
			if ne.Error() != c.str {
				t.Errorf("%T.Error() should be %v", c.err, c.str)
			}
		})
	}
}
