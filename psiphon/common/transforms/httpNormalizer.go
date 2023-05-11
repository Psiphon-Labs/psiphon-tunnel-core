/*
 * Copyright (c) 2023, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package transforms

import (
	"bytes"
	stderrors "errors"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

const (
	// httpNormalizerReadReqLineAndHeader HTTPNormalizer is waiting to finish
	// reading the Request-Line, and headers, of the next request from the
	// underlying net.Conn.
	httpNormalizerReadReqLineAndHeader = 0
	// httpNormalizerReadBody HTTPNormalizer is waiting to finish reading the
	// current request body from the underlying net.Conn.
	httpNormalizerReadBody = 1

	// httpNormalizerRequestLine is a valid Request-Line used by the normalizer.
	httpNormalizerRequestLine = "POST / HTTP/1.1"
	hostHeader                = "Host"
	contentLengthHeader       = "Content-Length"
	cookieHeader              = "Cookie"
	rangeHeader               = "Range"
)

var ErrPassthroughActive = stderrors.New("passthrough")

// HTTPNormalizer wraps a net.Conn, intercepting Read calls, and normalizes any
// HTTP requests that are read. The HTTP request components preceeding the body
// are normalized; i.e. the Request-Line and headers.
//
// Each HTTP request read from the underlying net.Conn is normalized and then
// returned over subsequent Read calls.
//
// HTTPNormalizer is not safe for concurrent use.
type HTTPNormalizer struct {
	// state is the HTTPNormalizer state. Possible values are
	// httpNormalizerReadReqLineAndHeader and httpNormalizerReadBody.
	state int64
	// b is used to buffer the accumulated bytes of the current request
	// until the Request-Line, and headers, are read from the underlying
	// net.Conn, normalized, and returned in one, or more, Read calls. May
	// contain bytes of the current request body and subsequent requests until
	// they are processed.
	b bytes.Buffer
	// maxReqLineAndHeadersSize is the maximum number of bytes the normalizer
	// will read before establishing a passthrough session, or rejecting the
	// connection, if the request body of the current request has not been
	// reached.
	// No limit is applied if the value is 0.
	maxReqLineAndHeadersSize int
	// scanIndex is the index that the bytes in b have been processed up to.
	// Bytes before this index in b will not contain the RequestLine, or
	// headers, of the current request after a Read call. Applies when state is
	// httpNormalizerReadReqLineAndHeader.
	scanIndex int
	// readRequestLine is set to true when the Request-Line of the current
	// request has been read. Applies when state is httpNormalizerReadReqLineAndHeader.
	readRequestLine bool
	// reqLineAndHeadersBuf is the buffer used to stage the next normalized
	// Request-Line, and headers, before outputting them in Read.
	reqLineAndHeadersBuf bytes.Buffer
	// headers is the staging area for preserved headers and is reset after the
	// Request-Line, and headers, of the current request are processed.
	headers map[string][]byte
	// contentLength of the current request. Reset after the Request-Line, and
	// headers, of the current request are processed
	contentLength *uint64
	// preserveHeaders are the headers to preserve during request normalization.
	preserveHeaders []string
	// prohibitedHeaders is a list of HTTP headers to check for in the
	// request. If one of these headers is found, then a passthrough is
	// performed. This is used to defend against abuse.
	// Limitation: prohibited headers are only logged when passthrough is
	// configured and passthroughLogPassthrough is set.
	prohibitedHeaders []string
	// headerWriteOrder is the order in which headers are written if set. Used
	// for testing.
	headerWriteOrder []string
	// readRemain is the number of remaining request body bytes of the current
	// request to read from the underlying net.Conn.
	readRemain uint64
	// copyRemain is the number of remaining bytes of the current request to
	// return over one, or more, Read calls.
	copyRemain uint64
	// validateMeekCookie is called with the cookie header value of the current
	// request when it is received and a passthrough session is established if
	// false is returned.
	// Note: if there are multiple cookie headers, even though prohibited by
	// rfc6265, then validateMeekCookie will only be invoked once with the
	// first one received.
	validateMeekCookie func(rawCookies []byte) ([]byte, error)
	// ValidateMeekCookieResult stores the result from calling
	// validateMeekCookie.
	ValidateMeekCookieResult []byte
	// passthrough is set if the normalizer has established a passthrough
	// session.
	passthrough bool
	// passthroughDialer is used to establish any passthrough sessions.
	passthroughDialer func(network, address string) (net.Conn, error)
	// passthroughAddress is the passthrough address that will be used for any
	// passthrough sessions.
	passthroughAddress string
	// passthroughLogPassthrough is called when a passthrough session is
	// initiated.
	passthroughLogPassthrough func(clientIP string, tunnelError error, logFields map[string]interface{})

	net.Conn
}

func NewHTTPNormalizer(conn net.Conn) *HTTPNormalizer {
	t := HTTPNormalizer{
		Conn: conn,
	}

	// TODO/perf: could pre-alloc n.b, and n.reqLineAndHeadersBuf,
	// with (*bytes.Buffer).Grow().

	t.reqLineAndHeadersBuf.WriteString(httpNormalizerRequestLine)

	t.preserveHeaders = []string{
		hostHeader,
		contentLengthHeader,
		cookieHeader,
		rangeHeader,
	}

	return &t
}

// Read implements the net.Conn interface.
//
// Note: it is assumed that the underlying transport, net.Conn, is a reliable
// stream transport, i.e. TCP, therefore it is required that the caller stop
// calling Read() on an instance of HTTPNormalizer after an error is returned
// because, following this assumption, the connection will have failed when a
// Read() call to the underlying net.Conn fails; a new connection must be
// established, net.Conn, and wrapped with a new HTTPNormalizer.
//
// Warning: Does not handle chunked encoding. Must be called synchronously.
func (t *HTTPNormalizer) Read(buffer []byte) (int, error) {

	if t.passthrough {
		return 0, io.EOF
	}

	// TODO/perf: allocate on-demand
	if t.headers == nil {
		t.headers = make(map[string][]byte)
	}

	if t.state == httpNormalizerReadReqLineAndHeader {

		// perf: read into caller's buffer instead of allocating a new one.
		// perf: theoretically it could be more performant to read directly
		// into t.b, but there is no mechanism to do so with bytes.Buffer.
		n, err := t.Conn.Read(buffer)

		if n > 0 {
			// Do not need to check return value. Applies to all subsequent
			// calls to t.b.Write() and this comment will not be repeated for
			// each. See https://github.com/golang/go/blob/1e9ff255a130200fcc4ec5e911d28181fce947d5/src/bytes/buffer.go#L164.
			t.b.Write(buffer[:n])
		}

		crlf := []byte("\r\n")
		doublecrlf := []byte("\r\n\r\n")

		// Check if the maximum number of bytes to read before the request body
		// has been exceeded first.
		// Note: could check if max header size will be exceeded before Read
		// call or ensure the buffer passed into Read is no larger than
		// t.maxReqLineAndHeadersSize-t.b.Len().
		if t.maxReqLineAndHeadersSize > 0 && t.b.Len() > t.maxReqLineAndHeadersSize && !bytes.Contains(t.b.Bytes()[:t.maxReqLineAndHeadersSize], doublecrlf) {

			if t.passthroughConfigured() {

				t.startPassthrough(errors.TraceNew("maxReqLineAndHeadersSize exceeded before request body received"), nil)

				return 0, nil
			}

			return 0, errors.Tracef("%d exceeds maxReqLineAndHeadersSize %d", t.b.Len(), t.maxReqLineAndHeadersSize)
		}

		if err != nil {
			// Do not wrap any I/O err returned by Conn
			return 0, err
		}

		// preserve headers
		//
		// TODO/perf: instead of storing headers in a map they could be
		// processed and written as they are parsed, but benchmarking this
		// change shows no measurable change in performance.
		//
		// TODO/perf: skip Request-Line, e.g. "GET /foo HTTP/1.1"

		reachedBody := false

		for {

			// NOTE: could add guard here for t.scanIndex < t.b.Len(),
			// but should never happen.
			i := bytes.Index(t.b.Bytes()[t.scanIndex:], crlf)

			var header []byte
			if i == -1 {
				break // no more CRLF separated headers in t.b
			} else {
				header = t.b.Bytes()[t.scanIndex : t.scanIndex+i]
			}

			if len(header) == 0 && t.readRequestLine {
				// Zero-length header line means the end of the request headers
				// has been reached.
				reachedBody = true
				break
			}

			if !t.readRequestLine {
				t.readRequestLine = true
			}

			if len(t.headers) >= len(t.preserveHeaders) {
				t.scanIndex += i + len(crlf)
				continue // found all headers, continue until final CRLF
			}

			colon := bytes.Index(header, []byte(":"))
			if colon == -1 {
				t.scanIndex += i + len(crlf)
				continue // not a header, skip
			}

			// Allow for space before header and trim whitespace around
			// value.
			k := textproto.TrimBytes(header[:colon])
			v := textproto.TrimBytes(header[colon+1:]) // skip over ":"

			err = nil
			var logFields map[string]interface{}

			if t.validateMeekCookie != nil && t.ValidateMeekCookieResult == nil && bytes.Equal(k, []byte(cookieHeader)) {
				t.ValidateMeekCookieResult, err = t.validateMeekCookie(v)
				if err != nil {
					err = errors.TraceMsg(err, "invalid meek cookie")
				}
			}

			if err == nil {
				if bytes.Equal(k, []byte(contentLengthHeader)) {
					var cl uint64
					cl, err = strconv.ParseUint(string(v), 10, 63)
					if err != nil {
						err = errors.TraceMsg(err, "invalid Content-Length")
					} else {
						t.contentLength = &cl
					}
				}
			}

			if err == nil {
				// Do passthrough if a prohibited header is found
				for _, h := range t.prohibitedHeaders {

					// TODO/perf: consider using map, but array may be faster
					// and use less mem.
					if bytes.Equal(k, []byte(h)) {

						err = errors.TraceNew("prohibited header")
						logFields = map[string]interface{}{
							"header": h,
							"value":  v,
						}

						break
					}
				}
			}

			if err != nil {
				if t.passthroughConfigured() {
					t.startPassthrough(err, logFields)
					return 0, nil
				} else {
					return 0, errors.Trace(err)
				}
			}

			for _, h := range t.preserveHeaders {
				// TODO/perf: consider using map, but array may be faster and
				// use less mem.
				if bytes.Equal(k, []byte(h)) {
					// TODO: if there are multiple preserved headers with the
					// same key, then the last header parsed will be the
					// preserved value. Consider if this is the desired
					// functionality.
					t.headers[h] = v
					break
				}
			}

			t.scanIndex += i + len(crlf)
		}

		if !reachedBody {
			return 0, nil
		} // else: Request-Line and all headers have been read.

		bodyOffset := t.scanIndex + len(crlf)

		// reset for next request
		defer func() {
			t.scanIndex = 0
			t.readRequestLine = false
			t.headers = nil
			t.contentLength = nil
		}()

		err = nil

		if t.contentLength == nil {
			// Irrecoverable error because either Content-Length header
			// is missing, or Content-Length header value is empty, e.g.
			// "Content-Length: ", and request body length cannot be
			// determined.
			err = errors.TraceNew("Content-Length missing")
		}

		if err == nil {
			if t.validateMeekCookie != nil {
				// NOTE: could check t.ValidateMeekCookieResult == nil instead
				// if it is guaranteed to return a non-nil result if no error is
				// returned.
				if _, ok := t.headers[cookieHeader]; !ok {
					err = errors.TraceNew("cookie missing")
				}
			}
		}

		if err != nil {
			if t.passthroughConfigured() {
				t.startPassthrough(err, nil)
				return 0, nil
			} else {
				return 0, errors.Trace(err)
			}
		}

		// No passthrough will be performed. Discard buffered bytes because
		// they are no longer needed to perform a passthrough.
		t.b.Next(bodyOffset)

		// TODO: technically at this point we could start copying bytes into the
		// caller's buffer which would remove the need to copy len(buffer) bytes
		// twice; first into the internal buffer and second into the caller's
		// buffer.
		t.reqLineAndHeadersBuf.Truncate(len(httpNormalizerRequestLine))

		if _, ok := t.headers[hostHeader]; !ok {
			// net/http expects the host header
			t.reqLineAndHeadersBuf.WriteString("\r\nHost: example.com")
		}

		// Write headers

		if t.headerWriteOrder != nil {
			// Re-add headers in specified order (for testing)
			for _, k := range t.headerWriteOrder {
				if v, ok := t.headers[k]; ok {
					t.reqLineAndHeadersBuf.WriteString("\r\n" + k + ": ")
					t.reqLineAndHeadersBuf.Write(v)
				}
			}
		} else {
			for k, v := range t.headers {
				t.reqLineAndHeadersBuf.WriteString("\r\n" + k + ": ")
				t.reqLineAndHeadersBuf.Write(v)
			}
		}
		t.reqLineAndHeadersBuf.Write(doublecrlf)

		// TODO/perf: could eliminate copy of header by copying it direct into
		// the caller's buffer instead of copying the bytes over to t.b first.
		header := t.reqLineAndHeadersBuf.Bytes()

		// Copy any request body bytes received before resetting the
		// buffer.
		var reqBody []byte
		reqBodyLen := t.b.Len() // number of request body bytes received
		if reqBodyLen > 0 {
			reqBody = make([]byte, reqBodyLen)
			copy(reqBody, t.b.Bytes())
		}

		t.b.Reset()
		t.b.Write(header)
		if len(reqBody) > 0 {
			t.b.Write(reqBody)
		}

		// Calculate number of bytes remaining to:
		// - read from the underlying net.Conn
		// - return to the caller

		t.state = httpNormalizerReadBody

		totalReqBytes := len(header) + int(*t.contentLength)
		t.copyRemain = uint64(totalReqBytes)

		bytesOfBodyRead := t.b.Len() - len(header)

		if bytesOfBodyRead > totalReqBytes-len(header) {
			t.readRemain = 0
		} else {
			t.readRemain = *t.contentLength - uint64(bytesOfBodyRead)
		}

		return t.copy(buffer), nil
	}

	// Request-Line, and headers, have been normalized. Return any remaining
	// bytes of these and then read, and return, the bytes of the request body
	// from the underlying net.Conn.

	var n int
	var err error

	// Read more bytes from the underlying net.Conn once all the remaining
	// bytes in t.b have been copied into the caller's buffer in previous Read
	// calls.
	if t.b.Len() == 0 {

		// perf: read bytes directly into the caller's buffer.

		bufferLen := len(buffer)
		if uint64(bufferLen) > t.readRemain {
			bufferLen = int(t.readRemain)
		}

		// TODO: could attempt to read more bytes and only copy bufferLen bytes
		// into buffer but this adds an extra copy.
		n, err = t.Conn.Read(buffer[:bufferLen])

		if uint64(n) >= t.readRemain {
			t.readRemain = 0
			// Do not reset t.b because it may contain bytes of subsequent
			// requests.
			t.state = httpNormalizerReadReqLineAndHeader
		} else {
			t.readRemain -= uint64(n)
		}

		// Do not wrap any I/O err returned by Conn
		return n, err
	}

	// Copy remaining bytes in t.b into the caller's buffer.
	return t.copy(buffer), nil
}

func (t *HTTPNormalizer) copy(buffer []byte) int {
	// Do not return any bytes from subsequent requests which have been
	// buffered internally because they need to be normalized first.
	bytesToCopy := t.copyRemain
	if uint64(t.b.Len()) < t.copyRemain {
		bytesToCopy = uint64(t.b.Len())
	}

	// Copy bytes to caller's buffer
	n := copy(buffer, t.b.Bytes()[:bytesToCopy])

	// Remove returned bytes from internal buffer and update number of bytes
	// remaining to return to the caller.
	t.b.Next(n) // perf: advance read cursor instead of copying bytes to front of buffer
	t.copyRemain -= uint64(n)

	if t.copyRemain == 0 && t.readRemain == 0 {

		// Shift buffer back to 0 copying any remaining bytes to the start of
		// the buffer.
		// TODO/perf: technically bytes.Buffer takes a similar, and more
		// efficient, approach internally so this should not be necessary.
		nextBytes := t.b.Bytes()
		t.b.Reset()
		if len(nextBytes) > 0 {
			t.b.Write(nextBytes)
		}

		// All bytes of the current request have been read and returned to the
		// caller. Start normalizing the header of the next request.
		// NOTE: if t.b contains CRLF separated lines, of the next request and
		// there is remaining space in the buffer supplied by the caller, then
		// technically we could start processing the next request instead of
		// returning here.

		// Do not reset t.b because it may contain bytes of subsequent requests.
		t.state = httpNormalizerReadReqLineAndHeader
	}

	return n
}

func (t *HTTPNormalizer) passthroughConfigured() bool {
	return t.passthroughDialer != nil && t.passthroughAddress != ""
}

func (t *HTTPNormalizer) startPassthrough(tunnelError error, logFields map[string]interface{}) {

	if t.passthroughLogPassthrough != nil {

		clientAddr := t.Conn.RemoteAddr().String()
		clientIP, _, _ := net.SplitHostPort(clientAddr)

		t.passthroughLogPassthrough(clientIP, errors.TraceMsg(tunnelError, "passthrough"), logFields)
	}

	go passthrough(t.Conn, t.passthroughAddress, t.passthroughDialer, t.b.Bytes())

	t.passthrough = true
}

func passthrough(conn net.Conn, address string, dialer func(network, address string) (net.Conn, error), buf []byte) {

	// Perform the passthrough relay.
	//
	// Limitations:
	//
	// - The local TCP stack may differ from passthrough target in a
	//   detectable way.
	//
	// - There may be detectable timing characteristics due to the network hop
	//   to the passthrough target.
	//
	// - Application-level socket operations may produce detectable
	//   differences (e.g., CloseWrite/FIN).
	//
	// - The dial to the passthrough, or other upstream network operations,
	//   may fail. These errors are not logged.
	//
	// - There's no timeout on the passthrough dial and no time limit on the
	//   passthrough relay so that the invalid client can't detect a timeout
	//   shorter than the passthrough target; this may cause additional load.

	defer conn.Close()

	passthroughConn, err := dialer("tcp", address)
	if err != nil {
		return
	}
	_, err = passthroughConn.Write(buf)
	if err != nil {
		return
	}

	go func() {
		_, _ = io.Copy(passthroughConn, conn)
		passthroughConn.Close()
	}()

	_, _ = io.Copy(conn, passthroughConn)
}

func (t *HTTPNormalizer) Write(b []byte) (n int, err error) {
	if t.passthrough {
		return 0, ErrPassthroughActive
	}
	return t.Conn.Write(b)
}

func (t *HTTPNormalizer) Close() error {
	if t.passthrough {
		return nil
	}
	return t.Conn.Close()
}

func (t *HTTPNormalizer) SetDeadline(tt time.Time) error {
	if t.passthrough {
		return nil
	}
	return t.Conn.SetDeadline(tt)
}

func (t *HTTPNormalizer) SetReadDeadline(tt time.Time) error {
	if t.passthrough {
		return nil
	}
	return t.Conn.SetReadDeadline(tt)
}

func (t *HTTPNormalizer) SetWriteDeadline(tt time.Time) error {
	if t.passthrough {
		return nil
	}
	return t.Conn.SetReadDeadline(tt)
}

func (t *HTTPNormalizer) GetMetrics() common.LogFields {
	// Relay any metrics from the underlying conn.
	m, ok := t.Conn.(common.MetricsSource)
	if ok {
		return m.GetMetrics()
	}
	return nil
}

// Note: all config fields must be set before calling Accept.
type HTTPNormalizerListener struct {
	HeaderWriteOrder          []string
	MaxReqLineAndHeadersSize  int
	ProhibitedHeaders         []string
	PassthroughAddress        string
	PassthroughDialer         func(network, address string) (net.Conn, error)
	PassthroughLogPassthrough func(clientIP string, tunnelError error, logFields map[string]interface{})
	ValidateMeekCookie        func(clientIP string, rawCookies []byte) ([]byte, error)

	net.Listener
}

func (t *HTTPNormalizerListener) Accept() (net.Conn, error) {
	conn, err := t.Listener.Accept()
	if err != nil {
		// Do not wrap any err returned by Listener
		return nil, err
	}

	normalizer := NewHTTPNormalizer(conn)

	normalizer.headerWriteOrder = t.HeaderWriteOrder // for testing
	normalizer.maxReqLineAndHeadersSize = t.MaxReqLineAndHeadersSize
	normalizer.prohibitedHeaders = t.ProhibitedHeaders
	normalizer.passthroughAddress = t.PassthroughAddress
	normalizer.passthroughDialer = t.PassthroughDialer
	normalizer.passthroughLogPassthrough = t.PassthroughLogPassthrough

	if t.ValidateMeekCookie != nil {

		clientIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			return nil, errors.Trace(err)
		}

		normalizer.validateMeekCookie = func(cookie []byte) ([]byte, error) {

			b, err := t.ValidateMeekCookie(clientIP, cookie)
			if err != nil {
				return nil, errors.Trace(err)
			}

			return b, nil
		}
	}

	return normalizer, nil
}

func WrapListenerWithHTTPNormalizer(listener net.Listener) *HTTPNormalizerListener {
	return &HTTPNormalizerListener{
		Listener: listener,
	}
}
