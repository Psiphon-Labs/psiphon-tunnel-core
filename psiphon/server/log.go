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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	go_log "log"
	"os"

	"github.com/Psiphon-Inc/logrus"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
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
			"context": common.GetParentContext(),
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
	fields["context"] = common.GetParentContext()
	return log.WithFields(logrus.Fields(fields))
}

// LogRawFieldsWithTimestamp directly logs the supplied fields adding only
// an additional "timestamp" field. The stock "msg" and "level" fields are
// omitted. This log is emitted at the Error level. This function exists to
// support API logs which have neither a natural message nor severity; and
// omitting these values here makes it easier to ship these logs to existing
// API log consumers.
func (logger *ContextLogger) LogRawFieldsWithTimestamp(fields LogFields) {
	logger.WithFields(logrus.Fields(fields)).Error(
		customJSONFormatterLogRawFieldsWithTimestamp)
}

// NewLogWriter returns an io.PipeWriter that can be used to write
// to the global logger. Caller must Close() the writer.
func NewLogWriter() *io.PipeWriter {
	return log.Writer()
}

// CustomJSONFormatter is a customized version of logrus.JSONFormatter
type CustomJSONFormatter struct {
}

const customJSONFormatterLogRawFieldsWithTimestamp = "CustomJSONFormatter.LogRawFieldsWithTimestamp"

// Format implements logrus.Formatter. This is a customized version
// of the standard logrus.JSONFormatter adapted from:
// https://github.com/Sirupsen/logrus/blob/f1addc29722ba9f7651bc42b4198d0944b66e7c4/json_formatter.go
//
// The changes are:
// - "time" is renamed to "timestamp"
// - there's an option to omit the standard "msg" and "level" fields
//
func (f *CustomJSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	data := make(logrus.Fields, len(entry.Data)+3)
	for k, v := range entry.Data {
		switch v := v.(type) {
		case error:
			// Otherwise errors are ignored by `encoding/json`
			// https://github.com/Sirupsen/logrus/issues/137
			data[k] = v.Error()
		default:
			data[k] = v
		}
	}

	if t, ok := data["timestamp"]; ok {
		data["fields.timestamp"] = t
	}

	data["timestamp"] = entry.Time.Format(logrus.DefaultTimestampFormat)

	if entry.Message != customJSONFormatterLogRawFieldsWithTimestamp {

		if m, ok := data["msg"]; ok {
			data["fields.msg"] = m
		}

		if l, ok := data["level"]; ok {
			data["fields.level"] = l
		}

		data["msg"] = entry.Message
		data["level"] = entry.Level.String()
	}

	serialized, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal fields to JSON, %v", err)
	}

	return append(serialized, '\n'), nil
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
		return common.ContextError(err)
	}

	logWriter := os.Stderr

	if config.LogFilename != "" {
		logWriter, err = os.OpenFile(
			config.LogFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			return common.ContextError(err)
		}
	}

	log = &ContextLogger{
		&logrus.Logger{
			Out:       logWriter,
			Formatter: &CustomJSONFormatter{},
			Level:     level,
		},
	}

	return nil
}

func init() {

	// Suppress standard "log" package logging performed by other packages.
	// For example, "net/http" logs messages such as:
	// "http: TLS handshake error from <client-ip-addr>:<port>: [...]: i/o timeout"
	go_log.SetOutput(ioutil.Discard)

	log = &ContextLogger{
		&logrus.Logger{
			Out:       os.Stderr,
			Formatter: &CustomJSONFormatter{},
			Hooks:     make(logrus.LevelHooks),
			Level:     logrus.DebugLevel,
		},
	}
}
