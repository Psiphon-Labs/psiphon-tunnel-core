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

func TestAllLogModelsAndSorting(t *testing.T) {
	l := parseLogsAndTestExpectations(logLinesWithExpectations(), t)

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
}

func TestMessageLogsWithErrorAndContext(t *testing.T) {
	logs := []LogLineWithExpectation{
		// The following messages should parse into 4 distinct log models
		messageLogExpectation(`{"msg":"a", "level":"info"}`),
		messageLogExpectation(`{"msg":"a", "level":"info"}`),
		messageLogExpectation(`{"msg":"a", "level":"info", "error": "b"}`),
		messageLogExpectation(`{"msg":"a", "level":"info", "error": "b"}`),
		messageLogExpectation(`{"msg":"a", "level":"info", "context": "c"}`),
		messageLogExpectation(`{"msg":"a", "level":"info", "context": "c"}`),
		messageLogExpectation(`{"msg":"a", "level":"info", "error": "b", "context": "c"}`),
		messageLogExpectation(`{"msg":"a", "level":"info", "error": "b", "context": "c"}`),

		// The following messages should parse into 2 distinct log models
		messageLogExpectation(`{"msg":"b", "level":"info", "error": "b"}`),
		messageLogExpectation(`{"msg":"b", "level":"info", "context": "b"}`),

		// The following messages should parse into 2 distinct log models
		messageLogExpectation(`{"msg":"c", "level":"info"}`),
		messageLogExpectation(`{"msg":"c", "level":"warning"}`),
	}

	l := parseLogsAndTestExpectations(logs, t)

	numLogModels := len(l.MessageLogModels.modelStats)
	expectedUniqueModels := 8
	if numLogModels != expectedUniqueModels {
		t.Errorf("Expected %d message log models but found %d\n", expectedUniqueModels, numLogModels)
	}
}

func TestMessageLogsWithRedactedIpAddresses(t *testing.T) {
	logs := []LogLineWithExpectation{
		// The following messages should parse into 1 distinct log model
		messageLogExpectation(`{"msg":"a", "level":"info", "error": "1.1.1.1->2.2.2.2"}`),
		messageLogExpectation(`{"msg":"a", "level":"info", "error": "3.3.3.3->4.4.4.4"}`),
		messageLogExpectation(`{"msg":"a", "level":"info", "error": "1.1.1.1->2.2.2.2:1"}`),
		messageLogExpectation(`{"msg":"a", "level":"info", "error": "1.1.1.1->2.2.2.2:65535"}`),
	}

	l := parseLogsAndTestExpectations(logs, t)

	numLogModels := len(l.MessageLogModels.modelStats)
	expectedUniqueModels := 1
	if numLogModels != expectedUniqueModels {
		t.Errorf("Expected %d message log models but found %d\n", expectedUniqueModels, numLogModels)
	}
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

func parseLogsAndTestExpectations(expectations []LogLineWithExpectation, t *testing.T) (l *LogStats) {
	l = NewLogStats()

	for _, expectation := range expectations {
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
				t.Errorf("Unexpected error: < %s >, from log line: \"%s\"\n", err, expectation.log)
			}
		}

		// Check message expectation
		if expectation.expects.message {
			if l.MessageLogModels.Count != snapshot.MessageLogModels.Count+1 {
				t.Errorf("Expected message log from: \"%s\"\n", expectation.log)
			}
		}

		// Check metric expectation
		if expectation.expects.metrics {
			if l.MetricsLogModels.Count != snapshot.MetricsLogModels.Count+1 {
				t.Errorf("Expected metric log model from: \"%s\"\n", expectation.log)
			}
		}

		// Check unknown expectation
		if expectation.expects.unknown {
			if l.UnknownLogModels.Count != snapshot.UnknownLogModels.Count+1 {
				t.Errorf("Expected unknown log model from: \"%s\"\n", expectation.log)
			}
		}
	}

	return l
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
