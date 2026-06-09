// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/pion/stun/v3"
)

// Dial connects to the remote agent, acting as the controlling ice agent.
// Dial blocks until at least one ice candidate pair has successfully connected.
func (a *Agent) Dial(ctx context.Context, remoteUfrag, remotePwd string) (*Conn, error) {
	return a.connect(ctx, true, remoteUfrag, remotePwd)
}

// Accept connects to the remote agent, acting as the controlled ice agent.
// Accept blocks until at least one ice candidate pair has successfully connected.
func (a *Agent) Accept(ctx context.Context, remoteUfrag, remotePwd string) (*Conn, error) {
	return a.connect(ctx, false, remoteUfrag, remotePwd)
}

// Conn represents the ICE connection.
// At the moment the lifetime of the Conn is equal to the Agent.
type Conn struct {
	bytesReceived atomic.Uint64
	bytesSent     atomic.Uint64
	agent         *Agent
}

// BytesSent returns the number of bytes sent.
func (c *Conn) BytesSent() uint64 {
	return c.bytesSent.Load()
}

// BytesReceived returns the number of bytes received.
func (c *Conn) BytesReceived() uint64 {
	return c.bytesReceived.Load()
}

func (a *Agent) connect(ctx context.Context, isControlling bool, remoteUfrag, remotePwd string) (*Conn, error) {
	err := a.loop.Err()
	if err != nil {
		return nil, err
	}
	err = a.startConnectivityChecks(isControlling, remoteUfrag, remotePwd) //nolint:contextcheck
	if err != nil {
		return nil, err
	}

	// Block until pair selected
	select {
	case <-a.loop.Done():
		return nil, a.loop.Err()
	case <-ctx.Done():
		return nil, ErrCanceledByCaller
	case <-a.onConnected:
	}

	return &Conn{
		agent: a,
	}, nil
}

// Read implements the Conn Read method.
func (c *Conn) Read(p []byte) (int, error) {
	err := c.agent.loop.Err()
	if err != nil {
		return 0, err
	}

	n, err := c.agent.buf.Read(p)
	c.bytesReceived.Add(uint64(n)) //nolint:gosec // G115

	return n, err
}

// Write implements the Conn Write method.
func (c *Conn) Write(packet []byte) (int, error) {
	err := c.agent.loop.Err()
	if err != nil {
		return 0, err
	}

	if stun.IsMessage(packet) {
		return 0, errWriteSTUNMessageToIceConn
	}

	pair := c.agent.getSelectedPair()
	if pair == nil {
		if err = c.agent.loop.Run(c.agent.loop, func(_ context.Context) {
			pair = c.agent.getBestValidCandidatePair()
		}); err != nil {
			return 0, err
		}

		if pair == nil {
			return 0, err
		}
	}

	// Write application data via the selected pair and update stats with actual bytes written.
	n, err := pair.Write(packet)
	if n > 0 {
		c.bytesSent.Add(uint64(n))
		pair.UpdatePacketSent(n)
	}

	return n, err
}

// GetCandidatePairsInfo returns snapshot information for all candidate pairs.
// Use the returned ID with WriteToPair() to write to a specific pair.
func (c *Conn) GetCandidatePairsInfo() []CandidatePairInfo {
	var pairs []CandidatePairInfo

	err := c.agent.loop.Run(c.agent.loop, func(_ context.Context) {
		pairs = make([]CandidatePairInfo, 0, len(c.agent.checklist))
		for _, cp := range c.agent.checklist {
			pairs = append(pairs, CandidatePairInfo{
				ID:                   cp.id,
				LocalCandidateType:   cp.Local.Type(),
				RemoteCandidateType:  cp.Remote.Type(),
				State:                cp.state,
				Nominated:            cp.nominated,
				CurrentRoundTripTime: time.Duration(atomic.LoadInt64(&cp.currentRoundTripTime)),
				RenominationQuality:  c.agent.evaluateCandidatePairQuality(cp),
			})
		}
	})
	if err != nil {
		return nil
	}

	return pairs
}

// WriteToPair writes packet to a specific candidate pair identified by its ID.
// Returns ErrCandidatePairNotFound if the pair ID is not found.
// Returns ErrCandidatePairNotSucceeded if the pair is not in Succeeded state.
// This is useful for sending packets over alternate paths
// even if they are not nominated.
func (c *Conn) WriteToPair(pairID uint64, packet []byte) (int, error) {
	if err := c.agent.loop.Err(); err != nil {
		return 0, err
	}

	if stun.IsMessage(packet) {
		return 0, errWriteSTUNMessageToIceConn
	}

	var pair *CandidatePair
	var lookupErr error

	if err := c.agent.loop.Run(c.agent.loop, func(_ context.Context) {
		pair = c.agent.pairsByID[pairID]
		if pair == nil {
			lookupErr = ErrCandidatePairNotFound

			return
		}
		if pair.state != CandidatePairStateSucceeded {
			lookupErr = ErrCandidatePairNotSucceeded
		}
	}); err != nil {
		return 0, err
	}

	if lookupErr != nil {
		return 0, lookupErr
	}

	n, err := pair.Write(packet)
	if n > 0 {
		pair.UpdatePacketSent(n)
	}

	return n, err
}

// Close implements the Conn Close method. It is used to close
// the connection. Any calls to Read and Write will be unblocked and return an error.
func (c *Conn) Close() error {
	return c.agent.Close()
}

// LocalAddr returns the local address of the current selected pair or nil if there is none.
func (c *Conn) LocalAddr() net.Addr {
	pair := c.agent.getSelectedPair()
	if pair == nil {
		return nil
	}

	return pair.Local.addr()
}

// RemoteAddr returns the remote address of the current selected pair or nil if there is none.
func (c *Conn) RemoteAddr() net.Addr {
	pair := c.agent.getSelectedPair()
	if pair == nil {
		return nil
	}

	return pair.Remote.addr()
}

// SetDeadline sets both read and write deadlines on the underlying ICE connection.
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}

	return c.SetWriteDeadline(t)
}

// SetReadDeadline sets the read deadline on the packet buffer used for application data.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.agent.buf.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the currently selected local candidate connection.
// The deadline applies to the selected candidate pair and will affect all traffic over that pair.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	pair := c.agent.getSelectedPair()
	if pair == nil || pair.Local == nil {
		return nil
	}

	if d, ok := pair.Local.(interface {
		setWriteDeadline(time.Time) error
	}); ok {
		return d.setWriteDeadline(t)
	}

	return nil
}
