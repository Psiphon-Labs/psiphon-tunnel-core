/*
 * Copyright (c) 2016, Psiphon Inc.
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
	"io"
	"os"

	"github.com/Psiphon-Inc/logrus"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// ContextLogger adds context logging functionality to the
// underlying logging packages.
type ContextLogger struct {
	*logrus.Logger
}

// LogFields is an alias for the field struct in the
// underlying logging package.
type LogFields logrus.Fields

// WithContext adds a "context" field containing the caller's
// function name and source file line number. Use this function
// when the log has no fields.
func (logger *ContextLogger) WithContext() *logrus.Entry {
	return log.WithFields(
		logrus.Fields{
			"context": psiphon.GetParentContext(),
		})
}

// WithContextFields adds a "context" field containing the caller's
// function name and source file line number. Use this function
// when the log has fields. Note that any existing "context" field
// will be renamed to "field.context".
func (logger *ContextLogger) WithContextFields(fields LogFields) *logrus.Entry {
	_, ok := fields["context"]
	if ok {
		fields["fields.context"] = fields["context"]
	}
	fields["context"] = psiphon.GetParentContext()
	return log.WithFields(logrus.Fields(fields))
}

// NewLogWriter returns an io.PipeWriter that can be used to write
// to the global logger. Caller must Close() the writer.
func NewLogWriter() *io.PipeWriter {
	return log.Writer()
}

var log *ContextLogger

// InitLogging configures a logger according to the specified
// config params. If not called, the default logger set by the
// package init() is used.
// Concurrenty note: should only be called from the main
// goroutine.
func InitLogging(config *Config) error {

	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		return psiphon.ContextError(err)
	}

	logWriter := os.Stderr

	if config.LogFilename != "" {
		logWriter, err = os.OpenFile(
			config.LogFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			return psiphon.ContextError(err)
		}
	}

	log = &ContextLogger{
		&logrus.Logger{
			Out:       logWriter,
			Formatter: &logrus.JSONFormatter{},
			Level:     level,
		},
	}

	return nil
}

func init() {
	log = &ContextLogger{
		&logrus.Logger{
			Out:       os.Stderr,
			Formatter: &logrus.JSONFormatter{},
			Hooks:     make(logrus.LevelHooks),
			Level:     logrus.DebugLevel,
		},
	}
}
