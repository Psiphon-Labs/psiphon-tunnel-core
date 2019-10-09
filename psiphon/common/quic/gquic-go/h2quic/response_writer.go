package h2quic

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/Psiphon-Labs/net/http2"
	"github.com/Psiphon-Labs/net/http2/hpack"
	quic "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic/gquic-go"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic/gquic-go/internal/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic/gquic-go/internal/utils"
)

type responseWriter struct {
	dataStreamID protocol.StreamID
	dataStream   quic.Stream

	headerStream      quic.Stream
	headerStreamMutex *sync.Mutex

	header        http.Header
	status        int // status code passed to WriteHeader
	headerWritten bool

	logger utils.Logger
}

func newResponseWriter(
	headerStream quic.Stream,
	headerStreamMutex *sync.Mutex,
	dataStream quic.Stream,
	dataStreamID protocol.StreamID,
	logger utils.Logger,
) *responseWriter {
	return &responseWriter{
		header:            http.Header{},
		headerStream:      headerStream,
		headerStreamMutex: headerStreamMutex,
		dataStream:        dataStream,
		dataStreamID:      dataStreamID,
		logger:            logger,
	}
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) WriteHeader(status int) {
	if w.headerWritten {
		return
	}
	w.headerWritten = true
	w.status = status

	var headers bytes.Buffer
	enc := hpack.NewEncoder(&headers)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})

	for k, v := range w.header {
		for index := range v {
			enc.WriteField(hpack.HeaderField{Name: strings.ToLower(k), Value: v[index]})
		}
	}

	w.logger.Infof("Responding with %d", status)
	w.headerStreamMutex.Lock()
	defer w.headerStreamMutex.Unlock()
	h2framer := http2.NewFramer(w.headerStream, nil)
	err := h2framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      uint32(w.dataStreamID),
		EndHeaders:    true,
		BlockFragment: headers.Bytes(),
	})
	if err != nil {
		w.logger.Errorf("could not write h2 header: %s", err.Error())
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(200)
	}
	if !bodyAllowedForStatus(w.status) {
		return 0, http.ErrBodyNotAllowed
	}
	return w.dataStream.Write(p)
}

func (w *responseWriter) Flush() {}

// This is a NOP. Use http.Request.Context
func (w *responseWriter) CloseNotify() <-chan bool { return make(<-chan bool) }

// test that we implement http.Flusher
var _ http.Flusher = &responseWriter{}

// copied from http2/http2.go
// bodyAllowedForStatus reports whether a given response status code
// permits a body. See RFC 2616, section 4.4.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}
