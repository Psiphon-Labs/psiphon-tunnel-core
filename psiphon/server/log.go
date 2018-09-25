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
	"sync"
	"time"

	"github.com/Psiphon-Inc/rotate-safe-writer"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/sirupsen/logrus"
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
// function name and source file line number; and "host_id" and
// "build_rev" fields identifying this server and build.
// Use this function when the log has no fields.
func (logger *ContextLogger) WithContext() *logrus.Entry {
	return logger.WithFields(
		logrus.Fields{
			"context":   common.GetParentContext(),
			"host_id":   logHostID,
			"build_rev": logBuildRev,
		})
}

func renameLogFields(fields LogFields) {
	if _, ok := fields["context"]; ok {
		fields["fields.context"] = fields["context"]
	}
	if _, ok := fields["host_id"]; ok {
		fields["fields.host_id"] = fields["host_id"]
	}
	if _, ok := fields["build_rev"]; ok {
		fields["fields.build_rev"] = fields["build_rev"]
	}
}

// WithContextFields adds a "context" field containing the caller's
// function name and source file line number; and "host_id" and
// "build_rev" fields identifying this server and build.
// Use this function when the log has fields.
// Note that any existing "context"/"host_id"/"build_rev" field will
// be renamed to "field.<name>".
func (logger *ContextLogger) WithContextFields(fields LogFields) *logrus.Entry {
	renameLogFields(fields)
	fields["context"] = common.GetParentContext()
	fields["host_id"] = logHostID
	fields["build_rev"] = logBuildRev
	return logger.WithFields(logrus.Fields(fields))
}

// LogRawFieldsWithTimestamp directly logs the supplied fields adding only
// an additional "timestamp" field; and "host_id" and "build_rev" fields
// identifying this server and build. The stock "msg" and "level" fields are
// omitted. This log is emitted at the Error level. This function exists to
// support API logs which have neither a natural message nor severity; and
// omitting these values here makes it easier to ship these logs to existing
// API log consumers.
// Note that any existing "context"/"host_id"/"build_rev" field will
// be renamed to "field.<name>".
func (logger *ContextLogger) LogRawFieldsWithTimestamp(fields LogFields) {
	renameLogFields(fields)
	fields["host_id"] = logHostID
	fields["build_rev"] = logBuildRev
	logger.WithFields(logrus.Fields(fields)).Error(
		customJSONFormatterLogRawFieldsWithTimestamp)
}

// LogPanicRecover calls LogRawFieldsWithTimestamp with standard fields
// for logging recovered panics.
func (logger *ContextLogger) LogPanicRecover(recoverValue interface{}, stack []byte) {
	log.LogRawFieldsWithTimestamp(
		LogFields{
			"event_name":    "panic",
			"recover_value": recoverValue,
			"stack":         string(stack),
		})
}

type commonLogger struct {
	contextLogger *ContextLogger
}

func (logger *commonLogger) WithContext() common.LogContext {
	// Patch context to be correct parent
	return logger.contextLogger.WithContext().WithField("context", common.GetParentContext())
}

func (logger *commonLogger) WithContextFields(fields common.LogFields) common.LogContext {
	// Patch context to be correct parent
	return logger.contextLogger.WithContextFields(LogFields(fields)).WithField("context", common.GetParentContext())
}

func (logger *commonLogger) LogMetric(metric string, fields common.LogFields) {
	fields["event_name"] = metric
	logger.contextLogger.LogRawFieldsWithTimestamp(LogFields(fields))
}

// CommonLogger wraps a ContextLogger instance with an interface
// that conforms to common.Logger. This is used to make the ContextLogger
// available to other packages that don't import the "server" package.
func CommonLogger(contextLogger *ContextLogger) *commonLogger {
	return &commonLogger{
		contextLogger: contextLogger,
	}
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

	data["timestamp"] = entry.Time.Format(time.RFC3339)

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
var logHostID, logBuildRev string
var initLogging sync.Once

// InitLogging configures a logger according to the specified
// config params. If not called, the default logger set by the
// package init() is used.
// Concurrency notes: this should only be called from the main
// goroutine; InitLogging only has effect on the first call, as
// the logging facilities it initializes may be in use by other
// goroutines after that point.
func InitLogging(config *Config) (retErr error) {

	initLogging.Do(func() {

		logHostID = config.HostID
		logBuildRev = common.GetBuildInfo().BuildRev

		level, err := logrus.ParseLevel(config.LogLevel)
		if err != nil {
			retErr = common.ContextError(err)
			return
		}

		var logWriter io.Writer

		if config.LogFilename != "" {
			logWriter, err = rotate.NewRotatableFileWriter(config.LogFilename, 0666)
			if err != nil {
				retErr = common.ContextError(err)
				return
			}

			if !config.SkipPanickingLogWriter {

				// Use PanickingLogWriter, which will intentionally
				// panic when a Write fails. Set SkipPanickingLogWriter
				// if this behavior is not desired.
				//
				// Note that NewRotatableFileWriter will first attempt
				// a retry when a Write fails.
				//
				// It is assumed that continuing operation while unable
				// to log is unacceptable; and that the psiphond service
				// is managed and will restart when it terminates.
				//
				// It is further assumed that panicking will result in
				// an error that is externally logged and reported to a
				// monitoring system.
				//
				// TODO: An orderly shutdown may be preferred, as some
				// data will be lost in a panic (e.g., server_tunnel logs).
				// It may be possible to perform an orderly shutdown first
				// and then panic, or perform an orderly shutdown and
				// simulate a panic message that will be reported.

				logWriter = NewPanickingLogWriter(config.LogFilename, logWriter)
			}

		} else {
			logWriter = os.Stderr
		}

		log = &ContextLogger{
			&logrus.Logger{
				Out:       logWriter,
				Formatter: &CustomJSONFormatter{},
				Level:     level,
			},
		}
	})

	return retErr
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
