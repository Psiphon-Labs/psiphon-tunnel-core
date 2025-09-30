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
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Inc/rotate-safe-writer"
	udsipc "github.com/Psiphon-Inc/uds-ipc"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/stacktrace"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// TraceLogger adds single frame stack trace information to the underlying
// logging facilities.
type TraceLogger struct {
	*logrus.Logger
}

// LogFields is an alias for the field struct in the underlying logging
// package.
type LogFields logrus.Fields

// Add copies log fields from b to a, skipping fields which already exist,
// regardless of value, in a.
func (a LogFields) Add(b LogFields) {
	for name, value := range b {
		_, ok := a[name]
		if !ok {
			a[name] = value
		}
	}
}

// WithTrace adds a "trace" field containing the caller's function name and
// source file line number; and "host_id", "provider", and "build_rev" fields
// identifying this server and build. Use this function when the log has no
// fields.
func (logger *TraceLogger) WithTrace() *logrus.Entry {
	fields := logrus.Fields{
		"trace":     stacktrace.GetParentFunctionName(),
		"host_id":   logHostID,
		"build_rev": logBuildRev,
	}
	if logHostProvider != "" {
		fields["provider"] = logHostProvider
	}
	return logger.WithFields(fields)
}

func renameLogFields(fields LogFields) {
	if _, ok := fields["trace"]; ok {
		fields["fields.trace"] = fields["trace"]
	}
	if _, ok := fields["host_id"]; ok {
		fields["fields.host_id"] = fields["host_id"]
	}
	if _, ok := fields["provider"]; ok {
		fields["fields.provider"] = fields["provider"]
	}
	if _, ok := fields["build_rev"]; ok {
		fields["fields.build_rev"] = fields["build_rev"]
	}
}

// WithTraceFields adds a "trace" field containing the caller's function name
// and source file line number; and "host_id", "provider", and "build_rev"
// fields identifying this server and build. Use this function when the log
// has fields.
//
// Note that any existing "trace"/"host_id"/"provider"/build_rev" field will
// be renamed to "field.<name>".
func (logger *TraceLogger) WithTraceFields(fields LogFields) *logrus.Entry {
	renameLogFields(fields)
	fields["trace"] = stacktrace.GetParentFunctionName()
	fields["host_id"] = logHostID
	if logHostProvider != "" {
		fields["provider"] = logHostProvider
	}
	fields["build_rev"] = logBuildRev
	return logger.WithFields(logrus.Fields(fields))
}

// LogRawFieldsWithTimestamp directly logs the supplied fields adding only an
// additional "timestamp" field; and "host_id", "provider", and "build_rev"
// fields identifying this server and build. The stock "msg" and "level"
// fields are omitted.
//
// If JSON logging is enabled, this log is emitted at the Error level. This
// function exists to support API logs which have neither a natural message
// nor severity; and omitting these values here makes it easier to ship these
// logs to existing API log consumers.
//
// If protobuf logging is enabled, the LogFields map will be parsed and used
// to populate a protobuf message struct pointer which is then serialized and
// emitted to a local metrics socket.
//
// Note that any existing "trace"/"host_id"/"provider"/"build_rev" field will
// be renamed to "field.<name>".
func (logger *TraceLogger) LogRawFieldsWithTimestamp(fields LogFields) {
	if ShouldLogJSON() {
		renameLogFields(fields)
		fields["host_id"] = logHostID
		if logHostProvider != "" {
			fields["provider"] = logHostProvider
		}
		fields["build_rev"] = logBuildRev

		logger.WithFields(logrus.Fields(fields)).Error(
			customJSONFormatterLogRawFieldsWithTimestamp)
	}

	if ShouldLogProtobuf() {
		for _, protoMsg := range LogFieldsToProtobuf(fields) {
			if protoMsg == nil {
				logger.WithTrace().Error("failed to populate protobuf message struct")
				continue
			}

			serialized, err := proto.Marshal(protoMsg)
			if err != nil {
				logger.WithTrace().Errorf("failed to serialize protobuf message: %s", err.Error())
				continue
			}

			err = metricSocketWriter.WriteMessage(serialized)
			if err != nil {
				// The only error this can be is udsipc.ErrBufferFull
				logger.WithTrace().Error("metric socket write buffer is full: log dropped")
				continue
			}
		}
	}
}

// LogPanicRecover calls LogRawFieldsWithTimestamp with standard fields
// for logging recovered panics.
func (logger *TraceLogger) LogPanicRecover(recoverValue interface{}, stack []byte) {
	log.LogRawFieldsWithTimestamp(
		LogFields{
			"event_name":    "panic",
			"recover_value": recoverValue,
			"stack":         string(stack),
		})
}

type commonLogger struct {
	traceLogger *TraceLogger
}

func (logger *commonLogger) WithTrace() common.LogTrace {
	// Patch trace to be correct parent
	return logger.traceLogger.WithTrace().WithField(
		"trace", stacktrace.GetParentFunctionName())
}

func (logger *commonLogger) WithTraceFields(fields common.LogFields) common.LogTrace {
	// Patch trace to be correct parent
	return logger.traceLogger.WithTraceFields(LogFields(fields)).WithField(
		"trace", stacktrace.GetParentFunctionName())
}

func (logger *commonLogger) LogMetric(metric string, fields common.LogFields) {
	fields["event_name"] = metric
	logger.traceLogger.LogRawFieldsWithTimestamp(LogFields(fields))
}

func (logger *commonLogger) IsLogLevelDebug() bool {
	return logger.traceLogger.Level == logrus.DebugLevel
}

// CommonLogger wraps a TraceLogger instance with an interface that conforms
// to common.Logger. This is used to make the TraceLogger available to other
// packages that don't import the "server" package.
func CommonLogger(traceLogger *TraceLogger) *commonLogger {
	return &commonLogger{
		traceLogger: traceLogger,
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

var (
	useLogCallback int32
	logCallback    atomic.Value
)

// setLogCallback sets a callback that is invoked with each JSON log message.
// This facility is intended for use in testing only.
func setLogCallback(callback func([]byte)) {
	if callback == nil {
		atomic.StoreInt32(&useLogCallback, 0)
		return
	}
	atomic.StoreInt32(&useLogCallback, 1)
	logCallback.Store(callback)
}

const customJSONFormatterLogRawFieldsWithTimestamp = "CustomJSONFormatter.LogRawFieldsWithTimestamp"

// Format implements logrus.Formatter. This is a customized version
// of the standard logrus.JSONFormatter adapted from:
// https://github.com/Sirupsen/logrus/blob/f1addc29722ba9f7651bc42b4198d0944b66e7c4/json_formatter.go
//
// The changes are:
// - "time" is renamed to "timestamp"
// - there's an option to omit the standard "msg" and "level" fields
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
		return nil, fmt.Errorf("failed to marshal fields to JSON, %v", err)
	}

	if atomic.LoadInt32(&useLogCallback) == 1 {
		logCallback.Load().(func([]byte))(serialized)
	}

	return append(serialized, '\n'), nil
}

var log *TraceLogger
var logFormat, logHostID, logHostProvider, logBuildRev, logDestinationPrefix string
var metricSocketWriter *udsipc.Writer
var shouldLogJSON, shouldLogProtobuf bool
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
		logHostProvider = config.HostProvider
		logBuildRev = buildinfo.GetBuildInfo().BuildRev
		logFormat = config.LogFormat
		logDestinationPrefix = config.LogDestinationPrefix

		level, err := logrus.ParseLevel(config.LogLevel)
		if err != nil {
			retErr = errors.Trace(err)
			return
		}

		// To retain backwards compatibility, the zero-value for log format
		// should retain the existing behavior (JSON logging only).
		if logFormat == "" {
			logFormat = "json"
		}

		if !slices.Contains([]string{"json", "protobuf", "both"}, logFormat) {
			retErr = errors.Tracef("invalid log format: %s", logFormat)
			return
		}

		shouldLogProtobuf = (logFormat == "protobuf" || logFormat == "both")
		shouldLogJSON = (logFormat == "json" || logFormat == "both")

		var logWriter io.Writer

		if config.LogFilename != "" {

			retries, create, mode := config.GetLogFileReopenConfig()
			logWriter, err = rotate.NewRotatableFileWriter(
				config.LogFilename, retries, create, mode)
			if err != nil {
				retErr = errors.Trace(err)
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

		log = &TraceLogger{
			&logrus.Logger{
				Out:       logWriter,
				Formatter: &CustomJSONFormatter{},
				Level:     level,
			},
		}

		if shouldLogProtobuf {
			if logDestinationPrefix == "" {
				retErr = errors.TraceNew("LogDestinationPrefix must be set if protobuf logging is enabled")
				return
			}

			if config.MetricSocketPath == "" {
				retErr = errors.TraceNew("MetricSocketPath must be set if protobuf logging is enabled")
				return
			}

			metricSocketWriter, retErr = udsipc.NewWriter(config.MetricSocketPath)
			if retErr != nil {
				retErr = errors.Tracef("failed to start metric socket writer: %w", retErr)
				return
			}

			metricSocketWriter.Start()
		}
	})

	return retErr
}

func IsLogLevelDebug() bool {
	return log.Level == logrus.DebugLevel
}

func ShouldLogProtobuf() bool {
	return shouldLogProtobuf
}

func ShouldLogJSON() bool {
	return shouldLogJSON
}

func init() {
	// Suppress standard "log" package logging performed by other packages.
	// For example, "net/http" logs messages such as:
	// "http: TLS handshake error from <client-ip-addr>:<port>: [...]: i/o timeout"
	go_log.SetOutput(ioutil.Discard)

	// Set default format
	logFormat = "json"

	log = &TraceLogger{
		&logrus.Logger{
			Out:       os.Stderr,
			Formatter: &CustomJSONFormatter{},
			Hooks:     make(logrus.LevelHooks),
			Level:     logrus.DebugLevel,
		},
	}
}
