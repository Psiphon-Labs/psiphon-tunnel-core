package tg

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/redjack/marionette"
	"go.uber.org/zap"
)

func init() {
	marionette.RegisterPlugin("tg", "recv", Recv)
}

func Recv(ctx context.Context, fsm marionette.FSM, args ...interface{}) error {
	t0 := time.Now()

	logger := marionette.Logger.With(
		zap.String("plugin", "tg.recv"),
		zap.String("party", fsm.Party()),
		zap.String("state", fsm.State()),
	)

	if len(args) < 1 {
		return errors.New("tg.recv: not enough arguments")
	}

	name, ok := args[0].(string)
	if !ok {
		return errors.New("tg.recv: invalid grammar name argument type")
	}

	// Retrieve grammar by name.
	grammar := grammars[name]
	if grammar == nil {
		return errors.New("tg.recv: grammar not found")
	}

	// Retrieve data from the connection.
	ciphertext, err := fsm.Conn().Peek(-1, true)
	if err == io.EOF {
		return err
	} else if err != nil {
		logger.Error("cannot read from connection", zap.Error(err))
		return err
	}
	ciphertextN := len(ciphertext)

	// Verify incoming data can be parsed by the grammar.
	m := Parse(grammar.Name, string(ciphertext))
	if m == nil {
		logger.Debug("tg.recv: cannot parse buffer", zap.String("grammar", grammar.Name))
		return marionette.ErrRetryTransition
	}

	// Execute each cipher against the data.
	var data []byte
	for _, cipher := range grammar.Ciphers {
		if buf, err := cipher.Decrypt(fsm, []byte(m[cipher.Key()])); err != nil {
			logger.Error("cannot decrypt", zap.String("key", cipher.Key()), zap.Error(err))
			return err
		} else if len(buf) != 0 {
			data = append(data, buf...)
		}
	}

	// If any handlers matched and returned data then decode data as a cell.
	var plaintextN int
	if len(data) > 0 {
		var cell marionette.Cell
		if err := cell.UnmarshalBinary(data); err != nil {
			logger.Error("cannot unmarshal cell", zap.Error(err))
			return err
		} else if cell.UUID != fsm.UUID() {
			logger.Error("uuid mismatch", zap.Int("local", fsm.UUID()), zap.Int("remote", cell.UUID))
			return marionette.ErrUUIDMismatch
		}
		plaintextN = len(cell.Payload)

		if fsm.InstanceID() == 0 {
			if cell.InstanceID == 0 {
				logger.Error("instance id required")
				return errors.New("msg instance id required")
			}
			fsm.SetInstanceID(cell.InstanceID)
		}

		if err := fsm.StreamSet().Enqueue(&cell); err != nil {
			logger.Error("cannot enqueue cell", zap.Error(err))
			return err
		}
	}

	// Clear FSM's read buffer on success.
	if _, err := fsm.Conn().Seek(int64(len(ciphertext)), io.SeekCurrent); err != nil {
		logger.Error("cannot move buffer forward", zap.Error(err))
		return err
	}

	logger.Debug("msg received",
		zap.String("grammar", name),
		zap.Int("ciphertext", ciphertextN),
		zap.Int("plaintext", plaintextN),
		zap.Duration("t", time.Since(t0)),
	)

	return nil
}
