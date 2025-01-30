// Copyright 2018 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metrics

import (
	"io"

	"github.com/Jigsaw-Code/outline-sdk/transport"
)

type ProxyMetrics struct {
	ClientProxy int64
	ProxyTarget int64
	TargetProxy int64
	ProxyClient int64
}

type measuredConn struct {
	transport.StreamConn
	io.WriterTo
	readCount *int64
	io.ReaderFrom
	writeCount *int64
}

func (c *measuredConn) Read(b []byte) (int, error) {
	n, err := c.StreamConn.Read(b)
	*c.readCount += int64(n)
	return n, err
}

func (c *measuredConn) WriteTo(w io.Writer) (int64, error) {
	n, err := io.Copy(w, c.StreamConn)
	*c.readCount += n
	return n, err
}

func (c *measuredConn) Write(b []byte) (int, error) {
	n, err := c.StreamConn.Write(b)
	*c.writeCount += int64(n)
	return n, err
}

func (c *measuredConn) ReadFrom(r io.Reader) (n int64, err error) {
	if rf, ok := c.StreamConn.(io.ReaderFrom); ok {
		// Prefer ReadFrom if we are calling ReadFrom. Otherwise io.Copy will try WriteTo first.
		n, err = rf.ReadFrom(r)
	} else {
		n, err = io.Copy(c.StreamConn, r)
	}
	*c.writeCount += n
	return n, err
}

func MeasureConn(conn transport.StreamConn, bytesSent, bytesReceived *int64) transport.StreamConn {
	return &measuredConn{StreamConn: conn, writeCount: bytesSent, readCount: bytesReceived}
}
