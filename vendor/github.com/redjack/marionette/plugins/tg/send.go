package tg

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/redjack/marionette"
	"go.uber.org/zap"
)

func init() {
	marionette.RegisterPlugin("tg", "send", Send)
}

func Send(ctx context.Context, fsm marionette.FSM, args ...interface{}) error {
	t0 := time.Now()

	logger := marionette.Logger.With(
		zap.String("plugin", "tg.send"),
		zap.String("party", fsm.Party()),
		zap.String("state", fsm.State()),
	)

	if len(args) < 1 {
		return errors.New("not enough arguments")
	}

	name, ok := args[0].(string)
	if !ok {
		return errors.New("invalid grammar name argument type")
	}

	// Find grammar by name.
	grammar := grammars[name]
	if grammar == nil {
		logger.Error("grammar not found", zap.String("format", name))
		return errors.New("grammar not found")
	}

	// Randomly choose template and replace embedded placeholders.
	ciphertext := grammar.Templates[rand.Intn(len(grammar.Templates))]
	ciphertext = strings.Replace(ciphertext, "%%SERVER_LISTEN_IP%%", fsm.Host(), -1)
	for _, cipher := range grammar.Ciphers {
		var err error
		if ciphertext, err = encryptTo(fsm, cipher, ciphertext, logger); err != nil {
			logger.Error("cannot encrypt", zap.String("key", cipher.Key()), zap.Error(err))
			return fmt.Errorf("cannot encrypt: %q", err)
		}
	}

	// Write to outgoing connection.
	if _, err := fsm.Conn().Write([]byte(ciphertext)); err != nil {
		logger.Error("cannot write to connection", zap.Error(err))
		return err
	}

	logger.Debug("msg sent", zap.String("grammar", name), zap.Int("ciphertext", len(ciphertext)), zap.Duration("t", time.Since(t0)))
	return nil
}

func encryptTo(fsm marionette.FSM, cipher TemplateCipher, template string, logger *zap.Logger) (_ string, err error) {
	// Encode data from streams if there is capacity in the handler.
	var data []byte
	if capacity, err := cipher.Capacity(fsm); err != nil {
		return "", err
	} else if capacity > 0 {
		cell := fsm.StreamSet().Dequeue(capacity)
		if cell == nil {
			cell = marionette.NewCell(0, 0, capacity, marionette.CellTypeNormal)
		}

		// Assign ids and marshal to bytes.
		cell.UUID, cell.InstanceID = fsm.UUID(), fsm.InstanceID()
		if data, err = cell.MarshalBinary(); err != nil {
			return "", err
		}
	}

	value, err := cipher.Encrypt(fsm, template, data)
	if err != nil {
		return "", err
	}
	return strings.Replace(template, "%%"+cipher.Key()+"%%", string(value), -1), nil
}
