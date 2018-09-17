package io

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/redjack/marionette"
	"go.uber.org/zap"
)

func init() {
	marionette.RegisterPlugin("io", "gets", Gets)
}

func Gets(ctx context.Context, fsm marionette.FSM, args ...interface{}) error {
	t0 := time.Now()

	logger := marionette.Logger.With(
		zap.String("plugin", "io.gets"),
		zap.String("party", fsm.Party()),
		zap.String("state", fsm.State()),
	)

	if len(args) < 1 {
		return errors.New("not enough arguments")
	}
	exp, ok := args[0].(string)
	if !ok {
		return errors.New("invalid argument type")
	}

	// Read buffer to see if our expected data comes through.
	buf, err := fsm.Conn().Peek(len(exp), true)
	if err == io.EOF {
		return err
	} else if err != nil {
		logger.Error("cannot read from connection", zap.Error(err))
		return err
	} else if !bytes.Equal([]byte(exp), buf) {
		logger.Error("unexpected read", zap.String("data", string(buf)))
		return fmt.Errorf("unexpected data: %q", buf)
	}

	// Move buffer forward.
	if _, err := fsm.Conn().Seek(int64(len(buf)), io.SeekCurrent); err != nil {
		logger.Error("cannot move buffer forward", zap.Error(err))
		return err
	}

	logger.Debug("msg received", zap.Int("n", len(buf)), zap.Duration("t", time.Since(t0)))
	return nil
}
