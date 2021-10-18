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

// Package analysis implements heuristical frequency analysis of Psiphon Tunnel
// Core server logs. Log lines are parsed into 3 distinct log types: message,
// metrics and unknown. Under these log types the number of logs of each unique
// identifier is counted. The unique identifiers are as follows:
// message: "msg" field
// metrics: "event_name" field
// unknown: key graph
package analysis

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"regexp"
	"sort"

	"github.com/sirupsen/logrus"
)

type LogLevel int

const (
	LOG_LEVEL_UNKNOWN          = -1
	LOG_LEVEL_DEBUG   LogLevel = iota
	LOG_LEVEL_INFO
	LOG_LEVEL_WARNING
	LOG_LEVEL_ERROR
)

func (l LogLevel) String() string {
	switch l {
	default:
		return "Unknown"
	case LOG_LEVEL_UNKNOWN:
		return "Unknown"
	case LOG_LEVEL_DEBUG:
		return "Debug"
	case LOG_LEVEL_INFO:
		return "Info"
	case LOG_LEVEL_WARNING:
		return "Warning"
	case LOG_LEVEL_ERROR:
		return "Error"
	}
}

type MetricsLogEventName string
type MessageLogKey string
type MessageLogName string
type MessageLogContext string
type MessageLogError string
type LogFields logrus.Fields
type node map[string]interface{}

// Models for each psiphond log type

type LogModel interface {
	JsonString() string
	Print(bool, bool)
}

type BaseLogModel struct {
	Example string
	Node    node
}

type MessageLogModel struct {
	BaseLogModel
	Msg               MessageLogName
	Level             LogLevel
	MessageLogContext *MessageLogContext
	MessageLogError   *MessageLogError
}

type MetricsLogModel struct {
	BaseLogModel
	Event MetricsLogEventName
}

type UnknownLogModel struct {
	BaseLogModel
}

func (a *BaseLogModel) equal(b BaseLogModel) bool {
	return a.Node.equal(b.Node)
}

func (a *MessageLogModel) key() MessageLogKey {
	var errorString string
	var context string

	if a.MessageLogError != nil {
		errorString = string(*a.MessageLogError)
	}
	if a.MessageLogContext != nil {
		context = string(*a.MessageLogContext)
	}

	return MessageLogKey(fmt.Sprintf("(%s,%d, %s,%s)", a.Msg, a.Level, errorString, context))
}

func (a *MessageLogContext) equal(b *MessageLogContext) bool {
	if a != nil && b != nil {
		return *a == *b
	} else if a == nil && b == nil {
		return true
	}
	return false
}

func (a *MessageLogError) equal(b *MessageLogError) bool {
	if a != nil && b != nil {
		return *a == *b
	} else if a == nil && b == nil {
		return true
	}
	return false
}

func (a *MessageLogModel) equal(b MessageLogModel) bool {
	if a.Msg != b.Msg {
		return false
	} else if a.Level != b.Level {
		return false
	}

	return a.MessageLogContext.equal(b.MessageLogContext) && a.MessageLogError.equal(b.MessageLogError)
}

func (a *MetricsLogModel) equal(b MetricsLogModel) bool {
	return a.Event == b.Event
}

func (a *UnknownLogModel) equal(b UnknownLogModel) bool {
	return a.Node.equal(b.Node)
}

// equal returns true if both nodes have the same key graphs.
func (a *node) equal(b node) bool {
	for k, v := range *a {
		if val, ok := b[k]; ok {
			if reflect.TypeOf(v) != reflect.TypeOf(val) {
				return false
			}
			switch m := val.(type) {
			case nil:
				return true
			case node:
				vNode := v.(node)
				return vNode.equal(m)
			case []node:
				vNode := v.([]node)
				if len(vNode) != len(m) {
					return false
				}
				for i := range m {
					if !vNode[i].equal(m[i]) {
						return false
					}
				}
			default:
				log.Fatalf("Unexpected val.(type) of %v\n", reflect.TypeOf(val))
			}
		} else {
			return false
		}
	}
	return true
}

func (a *BaseLogModel) JsonString() string {
	b, err := json.Marshal(a.Node)
	if err != nil {
		log.Fatal(err)
	}
	return string(b)
}

func (a *BaseLogModel) Print(printStructure, printExample bool) {
	if printStructure {
		fmt.Printf("Structure: %s\n", a.JsonString())
	}
	if printExample {
		fmt.Println("ExampleText: ", a.Example)
	}
}

func (a *MessageLogModel) Print(printStructure, printExample bool) {
	fmt.Printf("MessageLog\n")
	fmt.Printf("MessageLogName: %s\n", a.Msg)

	if a.MessageLogError != nil {
		fmt.Printf("MessageLogError: %s\n", *a.MessageLogError)
	}
	if a.MessageLogContext != nil {
		fmt.Printf("MessageLogContext: %s\n", *a.MessageLogContext)
	}

	if printStructure {
		fmt.Printf("Structure: %s\n", a.JsonString())
	}
	if printExample {
		fmt.Println("ExampleText: ", a.Example)
	}
}

func (a *MetricsLogModel) Print(printStructure, printExample bool) {
	fmt.Printf("MetricsLog\n")
	fmt.Printf("MetricsLogEventName: %s\n", a.Event)
	if printStructure {
		fmt.Printf("Structure: %s\n", a.JsonString())
	}
	if printExample {
		fmt.Println("ExampleText: ", a.Example)
	}
}

func (a *UnknownLogModel) Print(printStructure, printExample bool) {
	fmt.Printf("UnknownLog\n")
	fmt.Printf("Structure: %s\n", a.JsonString())
	if printExample {
		fmt.Println("ExampleText: ", a.Example)
	}
}

// Stats for each log model

type LogModelStatsMetrics interface {
	NumLogs() uint
}

type LogModelStats struct {
	Count uint
}

type MessageLogModelStats struct {
	LogModelStats
	MessageLogModel
}

type MetricsLogModelStats struct {
	LogModelStats
	MetricsLogModel
}

type UnknownLogModelStats struct {
	LogModelStats
	UnknownLogModel
}

func (a MessageLogModelStats) NumLogs() uint {
	return a.Count
}

func (a MetricsLogModelStats) NumLogs() uint {
	return a.Count
}

func (a UnknownLogModelStats) NumLogs() uint {
	return a.Count
}

func (a *MessageLogModelStats) Print(printStructure, printExample bool) {
	a.MessageLogModel.Print(printStructure, printExample)
}

func (a *MetricsLogModelStats) Print(printStructure, printExample bool) {
	a.MetricsLogModel.Print(printStructure, printExample)
}

func (a *UnknownLogModelStats) Print(printExample bool) {
	a.UnknownLogModel.Print(true, printExample)
}

func safeDivide(a, b float64) float64 {
	if b != 0 {
		return a / b
	}
	return 0
}

func (a *MessageLogModelStats) PrintWithRelativePercent(count uint, printStructure, printExample bool) {
	a.Print(printStructure, printExample)
	fmt.Printf("Count: %d of %d\n", a.Count, count)
	fmt.Printf("Percent: %0.2f\n", safeDivide(float64(a.Count), float64(count)))
	fmt.Printf("\n")
}

func (a *MetricsLogModelStats) PrintWithRelativePercent(count uint, printStructure, printExample bool) {
	a.Print(printStructure, printExample)
	fmt.Printf("Count: %d of %d\n", a.Count, count)
	fmt.Printf("Percent: %0.2f\n", safeDivide(float64(a.Count), float64(count)))
	fmt.Printf("\n")
}

func (a *UnknownLogModelStats) PrintWithRelativePercent(count uint, printExample bool) {
	a.Print(printExample)
	fmt.Printf("Count: %d of %d\n", a.Count, count)
	fmt.Printf("Percent: %0.2f\n", safeDivide(float64(a.Count), float64(count)))
	fmt.Printf("\n")
}

// Log type stats
// Aggregate log models by log type

type LogTypeStats struct {
	Count uint
}

type MessageLogStats struct {
	LogTypeStats
	modelStats map[MessageLogKey]*MessageLogModelStats
}

type MetricsLogStats struct {
	LogTypeStats
	modelStats map[MetricsLogEventName]*MetricsLogModelStats
}

type UnknownLogStats struct {
	LogTypeStats
	modelStats []UnknownLogModelStats
}

func (a *MessageLogStats) Print() {
	for _, v := range a.Sort() {
		v.PrintWithRelativePercent(a.Count, false, false)
	}
}

func (a *MetricsLogStats) Print() {
	for _, v := range a.Sort() {
		v.PrintWithRelativePercent(a.Count, false, false)
	}
}

func (a *UnknownLogStats) Print() {
	for _, v := range a.Sort() {
		v.PrintWithRelativePercent(a.Count, true)
	}
}

func (a *MessageLogStats) Sort() []MessageLogModelStats {
	var s []MessageLogModelStats
	for _, v := range a.modelStats {
		if v != nil {
			s = append(s, *v)
		}
	}

	sort.Slice(s, func(i, j int) bool {
		return s[j].Count > s[i].Count
	})

	return s
}

func (a *MetricsLogStats) Sort() []MetricsLogModelStats {
	var s []MetricsLogModelStats
	for _, v := range a.modelStats {
		if v != nil {
			s = append(s, *v)
		}
	}

	sort.Slice(s, func(i, j int) bool {
		return s[j].Count > s[i].Count
	})
	return s
}

func (a *UnknownLogStats) Sort() []UnknownLogModelStats {
	var s []UnknownLogModelStats
	s = append(s, a.modelStats...)

	sort.Slice(s, func(i, j int) bool {
		return s[j].Count > s[i].Count
	})
	return s
}

// Log file stats

type LogStats struct {
	MessageLogModels MessageLogStats
	MetricsLogModels MetricsLogStats
	UnknownLogModels UnknownLogStats
}

// NewLogStats initializes a new LogStats structure.
func NewLogStats() (l *LogStats) {
	l = &LogStats{
		MessageLogModels: MessageLogStats{
			modelStats: make(map[MessageLogKey]*MessageLogModelStats),
		},
		MetricsLogModels: MetricsLogStats{
			modelStats: make(map[MetricsLogEventName]*MetricsLogModelStats),
		},
		UnknownLogModels: UnknownLogStats{
			modelStats: nil,
		},
	}

	return l
}

func NewLogStatsFromFiles(files []string) (l *LogStats, err error) {
	l = NewLogStats()

	for _, file := range files {
		err = l.ParseFile(file)
		if err != nil {
			return nil, err
		}
	}

	return l, nil
}

// ParseFile takes a psiphond log file as input, parses the log lines into log
// models and updates the LogStats structure.
func (l *LogStats) ParseFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		err := l.ParseLogLine(scanner.Text())
		if err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

// ParseLogLine attempts to parse a log line into a log model and then updates the
// LogStats structure.
func (l *LogStats) ParseLogLine(log string) error {
	MessageLogModels := &l.MessageLogModels
	MetricsLogModels := &l.MetricsLogModels

	logModel, err := parseLogModel(log)
	if err != nil {
		return err
	}

	switch v := logModel.(type) {
	case *MessageLogModel:
		MessageLogModels.Count += 1

		if m, ok := MessageLogModels.modelStats[v.key()]; ok {
			m.Count += 1
		} else {
			MessageLogModels.modelStats[v.key()] = &MessageLogModelStats{LogModelStats{1}, *v}
		}
	case *MetricsLogModel:
		l.MetricsLogModels.Count += 1
		if m, ok := l.MetricsLogModels.modelStats[v.Event]; ok {
			m.Count += 1
		} else {
			MetricsLogModels.modelStats[v.Event] = &MetricsLogModelStats{LogModelStats{1}, *v}
		}
	case *UnknownLogModel:
		l.UnknownLogModels.Count += 1
		found := false
		for i := range l.UnknownLogModels.modelStats {
			if l.UnknownLogModels.modelStats[i].UnknownLogModel.equal(*v) {
				l.UnknownLogModels.modelStats[i].Count += 1
				found = true
				break
			}
		}
		if !found {
			l.UnknownLogModels.modelStats = append(l.UnknownLogModels.modelStats, UnknownLogModelStats{LogModelStats{1}, *v})
		}
	default:
		return fmt.Errorf("unexpected model type of %v", reflect.TypeOf(v))
	}

	return nil
}

func redactIpAddressesAndPorts(a string) string {
	ipAddressWithOptionalPort := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}(:(6553[0-5]|655[0-2][0-9]\d|65[0-4](\d){2}|6[0-4](\d){3}|[1-5](\d){4}|[1-9](\d){0,3}))?`)
	return ipAddressWithOptionalPort.ReplaceAllString(a, "<redacted>")
}

// parseLogModel attempts to parse a string into a log model. It is expected
// that the provided string is valid JSON.
func parseLogModel(s string) (LogModel, error) {
	var m LogFields
	err := json.Unmarshal([]byte(s), &m)
	if err != nil {
		return nil, fmt.Errorf("failed to parse log line into JSON: %s", err)
	}

	var l LogModel
	var b BaseLogModel
	b.Example = s
	b.Node = parseNode(&m)

	if m["event_name"] != nil {
		l = &MetricsLogModel{
			BaseLogModel: b,
			Event:        MetricsLogEventName(m["event_name"].(string)),
		}
	} else if m["msg"] != nil && m["level"] != nil {
		var level LogLevel
		switch m["level"].(string) {
		case "debug":
			level = LOG_LEVEL_DEBUG
		case "info":
			level = LOG_LEVEL_INFO
		case "warning":
			level = LOG_LEVEL_WARNING
		case "error":
			level = LOG_LEVEL_ERROR
		default:
			return nil, fmt.Errorf("unexpected log level: %s", m["level"].(string))
		}

		var context *MessageLogContext
		var err *MessageLogError

		if val, ok := m["context"]; ok {
			c := MessageLogContext(val.(string))
			context = &c
		}

		if val, ok := m["error"]; ok {
			errorWithIpsRedacted := redactIpAddressesAndPorts(val.(string))
			e := MessageLogError(errorWithIpsRedacted)
			err = &e
		}

		l = &MessageLogModel{
			BaseLogModel:      b,
			Msg:               MessageLogName(m["msg"].(string)),
			Level:             level,
			MessageLogContext: context,
			MessageLogError:   err,
		}
	} else {
		l = &UnknownLogModel{
			BaseLogModel: b,
		}
	}

	return l, nil
}

// parseNode takes a map and transforms it into a graph which represents its
// structure.
func parseNode(m *LogFields) node {
	n := make(node)
	for k, v := range *m {
		i := parseInterface(v)
		n[k] = i
	}
	return n
}

// parseInterface takes an interface and transforms it into a graph of its
// structure.
func parseInterface(i interface{}) interface{} {
	switch v := i.(type) {
	default:
		return nil
	case map[string]interface{}:
		l := LogFields(v)
		return parseNode(&l)
	case []interface{}:
		n := make([]node, 1)
		for i := range v {
			switch p := parseInterface(v[i]).(type) {
			case node:
				n = append(n, p)
			}
		}
		return n
	}
}

// sortLogModelsDescending merges all log models of different types and then
// sorts them in ascending order by the number times each occurs. Returns the
// sorted list and the total number of logs represented by each log model in
// the list.
func (l *LogStats) SortLogModels(messages, metrics, unknown bool) (models []interface{}, numLogs uint) {
	var messagesSort []MessageLogModelStats
	var metricsSort []MetricsLogModelStats
	var unknownSort []UnknownLogModelStats

	if messages {
		messagesSort = l.MessageLogModels.Sort()
		messages := make([]interface{}, len(messagesSort))
		for i, v := range messagesSort {
			messages[i] = v
		}
		models = append(models, messages...)
		numLogs += l.MessageLogModels.Count
	}

	if metrics {
		metricsSort = l.MetricsLogModels.Sort()
		metrics := make([]interface{}, len(metricsSort))
		for i, v := range metricsSort {
			metrics[i] = v
		}
		models = append(models, metrics...)
		numLogs += l.MetricsLogModels.Count
	}

	if unknown {
		unknownSort = l.UnknownLogModels.Sort()
		unknown := make([]interface{}, len(unknownSort))
		for i, v := range unknownSort {
			unknown[i] = v
		}
		models = append(models, unknown...)
		numLogs += l.UnknownLogModels.Count
	}

	sort.Slice(models, func(i, j int) bool {
		a := models[i].(LogModelStatsMetrics)
		b := models[j].(LogModelStatsMetrics)

		return b.NumLogs() > a.NumLogs()
	})

	return models, numLogs
}

// NumDistinctLogs returns the number of unique log models contained within the
// LogStats structure.
func (l *LogStats) NumDistinctLogs() uint {
	return uint(len(l.MessageLogModels.modelStats) + len(l.MetricsLogModels.modelStats) + len(l.UnknownLogModels.modelStats))
}

func (l *LogStats) Print(messages, metrics, unknown, printStructure, printExample bool) {
	logs, numLogs := l.SortLogModels(messages, metrics, unknown)

	for _, x := range logs {
		switch v := x.(type) {
		case MessageLogModelStats:
			v.PrintWithRelativePercent(numLogs, printStructure, printExample)
		case MetricsLogModelStats:
			v.PrintWithRelativePercent(numLogs, printStructure, printExample)
		case UnknownLogModelStats:
			v.PrintWithRelativePercent(numLogs, printExample)
		}
	}
}
