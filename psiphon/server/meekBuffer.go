/*
 * Copyright (c) 2017, Psiphon Inc.
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

package server

import (
	"errors"
	"io"
)

// CachedResponse is a data structure that supports meek
// protocol connection interruption resiliency: it stores
// payload data from the most recent response so that it
// may be resent if the client fails to receive it.
//
// The meek server maintains one CachedResponse for each
// meek client. Psiphon's variant of meek streams response
// data, so responses are not fixed size. To limit the memory
// overhead of response caching, each CachedResponse has a
// fixed-size buffer that operates as a ring buffer,
// discarding older response bytes when the buffer fills.
// A CachedResponse that has discarded data may still satisfy
// a client retry where the client has already received part
// of the response payload.
//
// A CachedResponse will also extend its capacity by
// borrowing buffers from a CachedResponseBufferPool, if
// available. When Reset is called, borrowed buffers are
// released back to the pool.
type CachedResponse struct {
	buffers            [][]byte
	readPosition       int
	readAvailable      int
	writeIndex         int
	writeBufferIndex   int
	overwriting        bool
	extendedBufferPool *CachedResponseBufferPool
}

// NewCachedResponse creates a CachedResponse with a fixed buffer
// of size bufferSize and borrowing buffers from extendedBufferPool.
func NewCachedResponse(
	bufferSize int,
	extendedBufferPool *CachedResponseBufferPool) *CachedResponse {

	return &CachedResponse{
		buffers:            [][]byte{make([]byte, bufferSize)},
		extendedBufferPool: extendedBufferPool,
	}
}

// Reset reinitializes the CachedResponse state to have
// no buffered response and releases all extended buffers
// back to the pool.
// Reset _must_ be called before discarding a CachedResponse
// or extended buffers will not be released.
func (response *CachedResponse) Reset() {
	for i, buffer := range response.buffers {
		if i > 0 {
			response.extendedBufferPool.Put(buffer)
		}
	}
	response.buffers = response.buffers[0:1]
	response.readPosition = 0
	response.readAvailable = 0
	response.writeIndex = 0
	response.writeBufferIndex = 0
	response.overwriting = false
}

// Available returns the size of the buffered response data.
func (response *CachedResponse) Available() int {
	return response.readAvailable
}

// HasPosition checks if the CachedResponse has buffered
// response data starting at or before the specified
// position.
func (response *CachedResponse) HasPosition(position int) bool {
	return response.readAvailable > 0 && response.readPosition <= position
}

// CopyFromPosition writes the response data, starting at
// the specified position, to writer. Any data before the
// position is skipped. CopyFromPosition will return an error
// if the specified position is not available.
// CopyFromPosition will copy no data and return no error if
// the position is at the end of its available data.
// CopyFromPosition can be called repeatedly to read the
// same data -- it does not advance or modify the CachedResponse.
func (response *CachedResponse) CopyFromPosition(
	position int, writer io.Writer) (int, error) {

	if response.readAvailable > 0 && response.readPosition > position {
		return 0, errors.New("position unavailable")
	}

	// Special case: position is end of available data
	if position == response.readPosition+response.readAvailable {
		return 0, nil
	}

	// Begin at the start of the response data, which may
	// be midway through the buffer(s).

	index := 0
	bufferIndex := 0
	if response.overwriting {
		index = response.writeIndex
		bufferIndex = response.writeBufferIndex
		if index >= len(response.buffers[bufferIndex]) {
			index = 0
			bufferIndex = (bufferIndex + 1) % len(response.buffers)
		}
	}

	// Iterate over all available data, skipping until at the
	// requested position.

	n := 0

	skip := position - response.readPosition
	available := response.readAvailable

	for available > 0 {

		buffer := response.buffers[bufferIndex]

		toCopy := min(len(buffer)-index, available)

		available -= toCopy

		if skip > 0 {
			if toCopy >= skip {
				index += skip
				toCopy -= skip
				skip = 0
			} else {
				skip -= toCopy
			}
		}

		if skip == 0 {
			written, err := writer.Write(buffer[index : index+toCopy])
			n += written
			if err != nil {
				return n, err
			}
		}

		index = 0
		bufferIndex = (bufferIndex + 1) % len(response.buffers)
	}

	return n, nil
}

// Write appends data to the CachedResponse. All writes will
// succeed, but only the most recent bytes will be retained
// once the fixed buffer is full and no extended buffers are
// available.
//
// Write may be called multiple times to record a single
// response; Reset should be called between responses.
//
// Write conforms to the io.Writer interface.
func (response *CachedResponse) Write(data []byte) (int, error) {

	dataIndex := 0

	for dataIndex < len(data) {

		// Write into available space in the current buffer

		buffer := response.buffers[response.writeBufferIndex]
		canWriteLen := len(buffer) - response.writeIndex
		needWriteLen := len(data) - dataIndex
		writeLen := min(canWriteLen, needWriteLen)

		if writeLen > 0 {
			copy(
				buffer[response.writeIndex:response.writeIndex+writeLen],
				data[dataIndex:dataIndex+writeLen])

			response.writeIndex += writeLen

			// readPosition tracks the earliest position in
			// the response that remains in the cached response.
			// Once the buffer is full (and cannot be extended),
			// older data is overwritten and readPosition advances.
			//
			// readAvailable is the amount of data in the cached
			// response, which may be less than the buffer capacity.

			if response.overwriting {
				response.readPosition += writeLen
			} else {
				response.readAvailable += writeLen
			}

			dataIndex += writeLen
		}

		if needWriteLen > canWriteLen {

			// Add an extended buffer to increase capacity

			// TODO: can extend whenever response.readIndex and response.readBufferIndex are 0?
			if response.writeBufferIndex == len(response.buffers)-1 &&
				!response.overwriting {

				extendedBuffer := response.extendedBufferPool.Get()
				if extendedBuffer != nil {
					response.buffers = append(response.buffers, extendedBuffer)
				}
			}

			// Move to the next buffer, which may wrap around

			// This isn't a general ring buffer: Reset is called at
			// start of each response, so the initial data is always
			// at the beginning of the first buffer. It follows that
			// data is overwritten once the buffer wraps around back
			// to the beginning.

			response.writeBufferIndex++
			if response.writeBufferIndex >= len(response.buffers) {
				response.writeBufferIndex = 0
				response.overwriting = true
			}
			response.writeIndex = 0
		}
	}

	return len(data), nil
}

// CachedResponseBufferPool is a fixed-size pool of
// fixed-size buffers that are used to temporarily extend
// the capacity of CachedResponses.
type CachedResponseBufferPool struct {
	bufferSize int
	buffers    chan []byte
}

// NewCachedResponseBufferPool creates a new CachedResponseBufferPool
// with the specified number of buffers. Buffers are allocated on
// demand and once allocated remain allocated.
func NewCachedResponseBufferPool(
	bufferSize, bufferCount int) *CachedResponseBufferPool {

	buffers := make(chan []byte, bufferCount)
	for i := 0; i < bufferCount; i++ {
		buffers <- make([]byte, 0)
	}

	return &CachedResponseBufferPool{
		bufferSize: bufferSize,
		buffers:    buffers,
	}
}

// Get returns a buffer, if one is available, or returns nil
// when no buffer is available. Get does not block. Call Put
// to release the buffer back to the pool.
//
// Note: currently, Buffers are not zeroed between use by
// different CachedResponses owned by different clients.
// A bug resulting in cross-client data transfer exposes
// only OSSH ciphertext in the case of meek's use of
// CachedResponses.
func (pool *CachedResponseBufferPool) Get() []byte {
	select {
	case buffer := <-pool.buffers:
		if len(buffer) == 0 {
			buffer = make([]byte, pool.bufferSize)
		}
		return buffer
	default:
		return nil
	}
}

// Put releases a buffer back to the pool. The buffer must
// have been obtained from Get.
func (pool *CachedResponseBufferPool) Put(buffer []byte) {
	pool.buffers <- buffer
}
