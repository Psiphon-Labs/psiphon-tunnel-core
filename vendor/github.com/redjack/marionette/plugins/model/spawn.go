package model

import (
	"context"
	"errors"
	"fmt"

	"github.com/redjack/marionette"
	"github.com/redjack/marionette/mar"
	"go.uber.org/zap"
)

func init() {
	marionette.RegisterPlugin("model", "spawn", Spawn)
}

func Spawn(ctx context.Context, fsm marionette.FSM, args ...interface{}) error {
	logger := marionette.Logger.With(
		zap.String("plugin", "model.spawn"),
		zap.String("party", fsm.Party()),
		zap.String("state", fsm.State()),
	)

	if len(args) < 2 {
		return errors.New("not enough arguments")
	}

	formatName, ok := args[0].(string)
	if !ok {
		return errors.New("invalid format name argument type")
	}

	n, ok := args[1].(int)
	if !ok {
		return errors.New("invalid count argument type")
	}

	// Find & parse format.
	data := mar.Format(formatName, "")
	if len(data) == 0 {
		logger.Error("cannot find format", zap.String("format", formatName))
		return fmt.Errorf("format not found: %q", formatName)
	}
	doc, err := mar.NewParser(fsm.Party()).Parse(data)
	if err != nil {
		logger.Error("cannot parse format", zap.String("format", formatName), zap.Error(err))
		return err
	}
	doc.Format = formatName

	// Execute a sub-FSM multiple times.
	for i := 0; i < n; i++ {
		logger.Debug("spawn begin", zap.Int("i", i))
		child := fsm.Clone(doc)
		if err := child.Execute(context.TODO()); err != nil {
			logger.Error("child execution failed", zap.Error(err))
			child.Reset()
			return err
		}
		child.Reset()
		logger.Debug("spawn end", zap.Int("i", i))
	}

	return nil
}
