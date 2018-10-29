/*
 * Copyright (c) 2018, Psiphon Inc.
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

package analysis

import (
	"reflect"
	"testing"
)

func TestLogLinesWithExpectations(t *testing.T) {
	l := NewLogStats()

	t.Run("test log model parsing", func(t *testing.T) {
		for _, expectation := range logLinesWithExpectations() {
			snapshot := *l

			err := l.ParseLogLine(expectation.log)

			// Check that the expectation is valid
			if !(expectation.expects.error || expectation.expects.message ||
				expectation.expects.metrics || expectation.expects.unknown) {
				t.Errorf("Malformed expectation expects nothing")
				t.FailNow()
			}

			// Check error expectation
			if err != nil {
				if expectation.expects.error != true {
					t.Errorf("Unexpected error from: %s\n", expectation.log)
				}
			}

			// Check message expectation
			if expectation.expects.message {
				if l.MessageLogModels.Count != snapshot.MessageLogModels.Count+1 {
					t.Errorf("Expected message log from: %s\n", expectation.log)
				}
			}

			// Check metric expectation
			if expectation.expects.metrics {
				if l.MetricsLogModels.Count != snapshot.MetricsLogModels.Count+1 {
					t.Errorf("Expected metric log model from: %s\n", expectation.log)
				}
			}

			// Check unknown expectation
			if expectation.expects.unknown {
				if l.UnknownLogModels.Count != snapshot.UnknownLogModels.Count+1 {
					t.Errorf("Expected unknown log model from: %s\n", expectation.log)
				}
			}
		}
	})

	t.Run("test log model sorting", func(t *testing.T) {
		logs, _ := l.SortLogModels(true, true, true)
		var prevLogCount uint

		for _, x := range logs {
			var count uint

			switch v := x.(type) {
			case MessageLogModelStats:
				count = v.Count
			case MetricsLogModelStats:
				count = v.Count
			case UnknownLogModelStats:
				count = v.Count
			default:
				t.Errorf("Encountered unexpected struct of type %v\n", reflect.TypeOf(v))
			}

			if prevLogCount != 0 && prevLogCount > count {
				t.Errorf("Expected list to be sorted in ascending order")
			}
			prevLogCount = count
		}
	})
}

// Helpers

type LogLineWithExpectation struct {
	log     string
	expects parseLineExpectation
}

type parseLineExpectation struct {
	error   bool
	message bool
	metrics bool
	unknown bool
}

func logLinesWithExpectations() (l []LogLineWithExpectation) {
	l = []LogLineWithExpectation{

		// ************
		// Message logs
		// ************

		// Test collision of basic message logs
		messageLogExpectation(`{"msg":"a", "level":"info"}`),
		messageLogExpectation(`{"msg":"a", "level":"info"}`),

		// Different valid levels
		messageLogExpectation(`{"msg":"a", "level":"debug"}`),
		messageLogExpectation(`{"msg":"a", "level":"warning"}`),
		messageLogExpectation(`{"msg":"a", "level":"error"}`),

		// ************
		// Metrics logs
		// ************

		// Test collision of basic metrics logs
		metricsLogExpectation(`{"event_name":"a"}`),
		metricsLogExpectation(`{"event_name":"a"}`),

		// ************
		// Unknown logs
		// ************

		unknownLogExpectation(`{}`),
		unknownLogExpectation(`{"a":"b"}`),

		// Test collision of unknown logs with depth
		unknownLogExpectation(`{"a":{"b":[{"c":{}}]}}`),
		unknownLogExpectation(`{"a":{"b":[{"c":{}}]}}`),

		// Message log line missing level field
		unknownLogExpectation(`{"msg":"a"}`),

		// **************
		// Malformed logs
		// **************

		malformedLogExpectation(`{`),
		// Invalid message log levels
		malformedLogExpectation(`{"msg":"a", "level":"{"}`),
		malformedLogExpectation(`{"msg":"a", "level":"unknown"}`),
	}

	return l
}

func messageLogExpectation(log string) LogLineWithExpectation {
	return LogLineWithExpectation{
		log: log,
		expects: parseLineExpectation{
			message: true,
		},
	}
}

func metricsLogExpectation(log string) LogLineWithExpectation {
	return LogLineWithExpectation{
		log: log,
		expects: parseLineExpectation{
			metrics: true,
		},
	}
}

func unknownLogExpectation(log string) LogLineWithExpectation {
	return LogLineWithExpectation{
		log: log,
		expects: parseLineExpectation{
			unknown: true,
		},
	}
}

func malformedLogExpectation(log string) LogLineWithExpectation {
	return LogLineWithExpectation{
		log: log,
		expects: parseLineExpectation{
			error: true,
		},
	}
}
