package io

import (
	"context"
	"errors"
	"time"

	"github.com/redjack/marionette"
	"go.uber.org/zap"
)

func init() {
	marionette.RegisterPlugin("io", "puts", Puts)
}

func Puts(ctx context.Context, fsm marionette.FSM, args ...interface{}) error {
	t0 := time.Now()

	logger := marionette.Logger.With(
		zap.String("plugin", "io.puts"),
		zap.String("party", fsm.Party()),
		zap.String("state", fsm.State()),
	)

	if len(args) < 1 {
		return errors.New("not enough arguments")
	}

	data, ok := args[0].(string)
	if !ok {
		return errors.New("invalid argument type")
	}
	n := len(data)

	// Keep attempting to send even if there are timeouts.
	for len(data) > 0 {
		n, err := fsm.Conn().Write([]byte(data))
		data = data[n:]
		if isTimeoutError(err) {
			logger.Debug("write timeout, retrying", zap.Error(err))
			continue
		} else if err != nil {
			logger.Error("cannot write to connection", zap.Error(err))
			return err
		}
	}

	logger.Debug("msg sent", zap.Int("n", n), zap.Duration("t", time.Since(t0)))

	return nil
}

// isTimeoutError returns true if the error is a timeout error.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	} else if err, ok := err.(interface{ Timeout() bool }); ok && err.Timeout() {
		return true
	}
	return false
}
