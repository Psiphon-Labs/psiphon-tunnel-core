package fte

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/redjack/marionette"
	"github.com/redjack/marionette/fte"
	"go.uber.org/zap"
)

func init() {
	marionette.RegisterPlugin("fte", "recv", Recv)
	marionette.RegisterPlugin("fte", "recv_async", RecvAsync)
}

// Recv receives data from a connection.
func Recv(ctx context.Context, fsm marionette.FSM, args ...interface{}) error {
	return recv(ctx, fsm, args, true)
}

// RecvAsync receives data from a connection without blocking.
func RecvAsync(ctx context.Context, fsm marionette.FSM, args ...interface{}) error {
	return recv(ctx, fsm, args, false)
}

func recv(ctx context.Context, fsm marionette.FSM, args []interface{}, blocking bool) error {
	t0 := time.Now()

	logger := func() *zap.Logger {
		return fsm.Logger().With(
			zap.String("plugin", "fte.recv"),
			zap.String("state", fsm.State()),
		)
	}

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

	// Retrieve data from the connection.
	conn := fsm.Conn()
	ciphertext, err := conn.Peek(-1, blocking)
	if err != nil && err != io.EOF {
		logger().Error("cannot read from connection", zap.Error(err))
		return err
	} else if len(ciphertext) == 0 {
		return nil
	}

	// Decode ciphertext.
	cipher, err := fsm.Cipher(regex, msgLen)
	if err != nil {
		return err
	}
	plaintext, remainder, err := cipher.Decrypt(ciphertext)
	logger().Debug("decrypt",
		zap.Int("plaintext", len(plaintext)),
		zap.Int("remainder", len(remainder)),
		zap.Int("ciphertext", len(ciphertext)),
		zap.Error(err),
	)
	if err == fte.ErrShortCiphertext {
		return nil
	} else if err != nil {
		logger().Error("cannot decrypt ciphertext", zap.Error(err))
		return err
	}

	// Unmarshal data.
	var cell marionette.Cell
	if err := cell.UnmarshalBinary(plaintext); err != nil {
		logger().Error("cannot unmarshal cell", zap.Error(err))
		return err
	}

	// Validate that the FSM & cell document UUIDs match.
	if fsm.UUID() != cell.UUID {
		logger().Error("uuid mismatch", zap.Int("local", fsm.UUID()), zap.Int("remote", cell.UUID))
		return marionette.ErrUUIDMismatch
	}

	// Set instance ID if it hasn't been set yet.
	// Validate ID if one has already been set.
	if fsm.InstanceID() == 0 {
		fsm.SetInstanceID(cell.InstanceID)
		return marionette.ErrRetryTransition
	} else if cell.InstanceID != 0 && fsm.InstanceID() != cell.InstanceID {
		logger().Error("instance id mismatch", zap.Int("local", fsm.InstanceID()), zap.Int("remote", cell.InstanceID))
		return fmt.Errorf("instance id mismatch: fsm=%d, cell=%d", fsm.InstanceID(), cell.InstanceID)
	}

	// Write plaintext to a cell decoder pipe.
	if err := fsm.StreamSet().Enqueue(&cell); err != nil {
		logger().Error("cannot enqueue cell", zap.Error(err))
		return err
	}

	// Move buffer forward by bytes consumed by the cipher.
	if _, err := conn.Seek(int64(len(ciphertext)-len(remainder)), io.SeekCurrent); err != nil {
		logger().Error("cannot move buffer forward", zap.Error(err))
		return err
	}

	logger().Debug("msg received",
		zap.Int("plaintext", len(cell.Payload)),
		zap.Int("ciphertext", len(ciphertext)),
		zap.Duration("t", time.Since(t0)),
	)

	return nil
}
