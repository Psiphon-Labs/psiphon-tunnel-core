package fte

import (
	"context"
	"errors"
	"time"

	"github.com/redjack/marionette"
	"github.com/redjack/marionette/fte"
	"go.uber.org/zap"
)

func init() {
	marionette.RegisterPlugin("fte", "send", Send)
	marionette.RegisterPlugin("fte", "send_async", SendAsync)
}

// Send sends data to a connection.
func Send(ctx context.Context, fsm marionette.FSM, args ...interface{}) error {
	return send(ctx, fsm, args, true)
}

// SendAsync send data to a connection without blocking.
func SendAsync(ctx context.Context, fsm marionette.FSM, args ...interface{}) error {
	return send(ctx, fsm, args, false)
}

func send(ctx context.Context, fsm marionette.FSM, args []interface{}, blocking bool) error {
	t0 := time.Now()

	logger := marionette.Logger.With(
		zap.String("plugin", "fte.send"),
		zap.Bool("blocking", blocking),
		zap.String("party", fsm.Party()),
		zap.String("state", fsm.State()),
	)

	if len(args) < 2 {
		return errors.New("not enough arguments")
	}

	regex, ok := args[0].(string)
	if !ok {
		return errors.New("invalid regex argument type")
	}
	msgLen, ok := args[1].(int)
	if !ok {
		return errors.New("invalid msg_len argument type")
	}

	cipher, err := fsm.Cipher(regex, msgLen)
	if err != nil {
		return err
	}
	capacity := cipher.Capacity() - fte.COVERTEXT_HEADER_LEN_CIPHERTTEXT - fte.CTXT_EXPANSION

	// Pull the next cell for the stream set. If no cell exists and we are
	// blocking then send an empty cell. If no cell exists and we are not
	// blocking then return. The FSM will move on to the next step. This
	// allows non-blocking send/recv to continually check both sides of a conn.
	cell := fsm.StreamSet().Dequeue(capacity)
	if cell != nil {
		// nop
	} else if cell == nil && blocking {
		logger.Debug("no cell, sending empty cell")
		cell = marionette.NewCell(0, 0, 0, marionette.CellTypeNormal)
	} else {
		return nil
	}

	// Assign fsm data to cell.
	cell.UUID, cell.InstanceID = fsm.UUID(), fsm.InstanceID()

	// Encode to binary.
	plaintext, err := cell.MarshalBinary()
	if err != nil {
		return err
	}

	// Encrypt using FTE cipher.
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		return err
	}

	// Write to outgoing connection.
	if _, err := fsm.Conn().Write(ciphertext); err != nil {
		return err
	}

	logger.Debug("msg sent",
		zap.Int("plaintext", len(cell.Payload)),
		zap.Int("ciphertext", len(ciphertext)),
		zap.Duration("t", time.Since(t0)),
	)
	return nil
}
