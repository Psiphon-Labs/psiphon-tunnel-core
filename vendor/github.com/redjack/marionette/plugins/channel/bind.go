package channel

import (
	"context"
	"errors"
	"time"

	"github.com/redjack/marionette"
	"go.uber.org/zap"
)

func init() {
	marionette.RegisterPlugin("channel", "bind", Bind)
}

// Bind binds the variable specified in the first argument to a port.
func Bind(ctx context.Context, fsm marionette.FSM, args ...interface{}) error {
	t0 := time.Now()

	logger := marionette.Logger.With(
		zap.String("plugin", "channel.bind"),
		zap.String("party", fsm.Party()),
		zap.String("state", fsm.State()),
	)

	if len(args) < 1 {
		return errors.New("not enough arguments")
	}

	name, ok := args[0].(string)
	if !ok {
		return errors.New("invalid argument type")
	}

	// Ignore if variable is already bound.
	if value := fsm.Var(name); value != nil {
		if i, _ := value.(int); i > 0 {
			logger.Debug("already bound", zap.Int("i", i))
			return nil
		}
	}

	// Create a new connection on a random port.
	port, err := fsm.Listen()
	if err != nil {
		logger.Error("cannot open listener", zap.Error(err))
		return err
	}

	// Save port number to variables.
	fsm.SetVar(name, port)

	logger.Debug("channel bound", zap.Int("port", port), zap.Duration("t", time.Since(t0)))

	return nil
}
