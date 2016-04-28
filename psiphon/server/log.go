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
	"log/syslog"
	"os"

	"github.com/Psiphon-Inc/logrus"
	logrus_syslog "github.com/Psiphon-Inc/logrus/hooks/syslog"
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
	return logrus.WithFields(
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

	hooks := make(logrus.LevelHooks)

	var syslogHook *logrus_syslog.SyslogHook

	if config.SyslogAddress != "" {

		syslogHook, err = logrus_syslog.NewSyslogHook(
			"udp",
			config.SyslogAddress,
			getSyslogPriority(config),
			config.SyslogTag)

		if err != nil {
			return psiphon.ContextError(err)
		}

		hooks.Add(syslogHook)
	}

	log = &ContextLogger{
		&logrus.Logger{
			Out:       os.Stderr,
			Formatter: new(logrus.TextFormatter),
			Hooks:     hooks,
			Level:     level,
		},
	}

	return nil
}

// getSyslogPriority determines golang's syslog "priority" value
// based on the provided config.
func getSyslogPriority(config *Config) syslog.Priority {

	// TODO: assumes log.Level filter applies?
	severity := syslog.LOG_DEBUG

	facilityCodes := map[string]syslog.Priority{
		"kern":     syslog.LOG_KERN,
		"user":     syslog.LOG_USER,
		"mail":     syslog.LOG_MAIL,
		"daemon":   syslog.LOG_DAEMON,
		"auth":     syslog.LOG_AUTH,
		"syslog":   syslog.LOG_SYSLOG,
		"lpr":      syslog.LOG_LPR,
		"news":     syslog.LOG_NEWS,
		"uucp":     syslog.LOG_UUCP,
		"cron":     syslog.LOG_CRON,
		"authpriv": syslog.LOG_AUTHPRIV,
		"ftp":      syslog.LOG_FTP,
		"local0":   syslog.LOG_LOCAL0,
		"local1":   syslog.LOG_LOCAL1,
		"local2":   syslog.LOG_LOCAL2,
		"local3":   syslog.LOG_LOCAL3,
		"local4":   syslog.LOG_LOCAL4,
		"local5":   syslog.LOG_LOCAL5,
		"local6":   syslog.LOG_LOCAL6,
		"local7":   syslog.LOG_LOCAL7,
	}

	facility, ok := facilityCodes[config.SyslogFacility]
	if !ok {
		facility = syslog.LOG_USER
	}

	return severity | facility
}

func init() {
	log = &ContextLogger{
		&logrus.Logger{
			Out:       os.Stderr,
			Formatter: new(logrus.TextFormatter),
			Hooks:     make(logrus.LevelHooks),
			Level:     logrus.DebugLevel,
		},
	}
}
