/*
 * Copyright (c) 2025, Psiphon Inc.
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

package testutils

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/stacktrace"
)

type TestLogger struct {
	logLevelDebug        int32
	component            string
	metricValidator      func(string, common.LogFields) bool
	packetMetrics        chan common.LogFields
	packetMetricsTimeout time.Duration
	hasValidMetric       int32
	hasInvalidMetric     int32
}

func NewTestLogger() *TestLogger {
	return &TestLogger{}
}

func NewTestLoggerWithPacketMetrics(
	packetMetricCount int,
	packetMetricsTimeout time.Duration) *TestLogger {
	return &TestLogger{
		packetMetrics:        make(chan common.LogFields, packetMetricCount),
		packetMetricsTimeout: packetMetricsTimeout,
	}
}

func NewTestLoggerWithComponent(
	component string) *TestLogger {

	return &TestLogger{
		component: component,
	}
}

func NewTestLoggerWithMetricValidator(
	component string,
	metricValidator func(string, common.LogFields) bool) *TestLogger {

	return &TestLogger{
		component:       component,
		metricValidator: metricValidator,
	}
}

func (logger *TestLogger) WithTrace() common.LogTrace {
	return &testLoggerTrace{
		logger: logger,
		trace:  stacktrace.GetParentFunctionName(),
	}
}

func (logger *TestLogger) WithTraceFields(fields common.LogFields) common.LogTrace {
	return &testLoggerTrace{
		logger: logger,
		trace:  stacktrace.GetParentFunctionName(),
		fields: fields,
	}
}

func (logger *TestLogger) LogMetric(metric string, fields common.LogFields) {

	if metric == "server_packet_metrics" && logger.packetMetrics != nil {
		select {
		case logger.packetMetrics <- fields:
		default:
		}
	}

	if logger.metricValidator != nil {
		if logger.metricValidator(metric, fields) {
			atomic.StoreInt32(&logger.hasValidMetric, 1)
		} else {
			atomic.StoreInt32(&logger.hasInvalidMetric, 1)
		}
		// Don't print log.
		return
	}

	jsonFields, _ := json.Marshal(fields)
	var component string
	if len(logger.component) > 0 {
		component = fmt.Sprintf("[%s]", logger.component)
	}
	fmt.Printf(
		"[%s]%s METRIC: %s: %s\n",
		time.Now().UTC().Format(time.RFC3339),
		component,
		metric,
		string(jsonFields))
}

func (logger *TestLogger) CheckMetrics(expectValidMetric bool) error {

	if expectValidMetric && atomic.LoadInt32(&logger.hasValidMetric) != 1 {
		return errors.TraceNew("missing valid metric")
	}
	if atomic.LoadInt32(&logger.hasInvalidMetric) == 1 {
		return errors.TraceNew("has invalid metric")
	}
	return nil
}

func (logger *TestLogger) GetNextPacketMetrics() common.LogFields {
	if logger.packetMetrics == nil {
		return nil
	}

	timer := time.NewTimer(logger.packetMetricsTimeout)
	defer timer.Stop()

	select {
	case fields := <-logger.packetMetrics:
		return fields
	case <-timer.C:
		return nil
	}
}

func (logger *TestLogger) IsLogLevelDebug() bool {
	return atomic.LoadInt32(&logger.logLevelDebug) == 1
}

func (logger *TestLogger) SetLogLevelDebug(logLevelDebug bool) {
	value := int32(0)
	if logLevelDebug {
		value = 1
	}
	atomic.StoreInt32(&logger.logLevelDebug, value)
}

type testLoggerTrace struct {
	logger *TestLogger
	trace  string
	fields common.LogFields
}

func (logger *testLoggerTrace) log(priority, message string) {
	now := time.Now().UTC().Format(time.RFC3339)
	var component string
	if len(logger.logger.component) > 0 {
		component = fmt.Sprintf("[%s]", logger.logger.component)
	}
	if len(logger.fields) == 0 {
		fmt.Printf(
			"[%s]%s %s: %s: %s\n",
			now, component, priority, logger.trace, message)
	} else {
		fields := common.LogFields{}
		for k, v := range logger.fields {
			switch v := v.(type) {
			case error:
				// Workaround for Go issue 5161: error types marshal to "{}"
				fields[k] = v.Error()
			default:
				fields[k] = v
			}
		}
		jsonFields, _ := json.Marshal(fields)
		fmt.Printf(
			"[%s]%s %s: %s: %s %s\n",
			now, component, priority, logger.trace, message, string(jsonFields))
	}
}

func (logger *testLoggerTrace) Debug(args ...interface{}) {
	if !logger.logger.IsLogLevelDebug() {
		return
	}
	logger.log("DEBUG", fmt.Sprint(args...))
}

func (logger *testLoggerTrace) Info(args ...interface{}) {
	logger.log("INFO", fmt.Sprint(args...))
}

func (logger *testLoggerTrace) Warning(args ...interface{}) {
	logger.log("WARNING", fmt.Sprint(args...))
}

func (logger *testLoggerTrace) Error(args ...interface{}) {
	logger.log("ERROR", fmt.Sprint(args...))
}
