package log

// Log is a custom wrapper around the default golang logging library that allows use of helper
// functions that implement logging levels.
//
// This exists because I don't want to modify the logging format of our existing log lines (i.e
// remove prefixes or modify timestamp) but I need to add logging level verbosity to clean up the
// things that we are logging. This should support all of the functionality of the default logging
// library PLUS log level functions. This should be a drop in replacement for the golang log library
// as all of the existing functionality is supported as of writing.

import (
	"fmt"
	"io"
	"log"
	"strings"
)

// Level provides a step of level that can be provided to indicate different
// logging verbosity
type Level int

const (
	// UnknownLevel indicates and unrecognized logging level
	UnknownLevel Level = -1

	// TraceLevel provides the most verbose logging
	TraceLevel Level = iota

	// DebugLevel provides verbose logging beyond regular function
	DebugLevel

	// WarnLevel provides slightly more verbose logging
	WarnLevel

	// ErrorLevel provides a "normal production" logging level
	ErrorLevel

	// InfoLevel provides only informational logging that would typically be written to stdout
	InfoLevel
)

var levelStrings = map[string]Level{
	"trace": TraceLevel,
	"debug": DebugLevel,
	"warn":  WarnLevel,
	"error": ErrorLevel,
	"info":  InfoLevel,
}

var level = ErrorLevel

// SetLevel Sets the log level for the log package function calls,
func SetLevel(l Level) {
	level = l
}

// ParseLevel takes a string and returns the equivalent log Level struct.
func ParseLevel(levelStr string) (Level, error) {
	lowerLevelStr := strings.ToLower(levelStr)
	for name, l := range levelStrings {
		if lowerLevelStr == name {
			return l, nil
		}
	}
	return UnknownLevel, fmt.Errorf("unknown logging level string provided: \"%s\"", levelStr)
}

// Fatal is equivalent to Print() followed by a call to os.Exit(1).
func Fatal(v ...interface{}) {
	log.Fatal(v...)
}

// Fatalf is equivalent to Printf() followed by a call to os.Exit(1).
func Fatalf(format string, v ...interface{}) {
	log.Fatalf(format, v...)
}

// Fatalln is equivalent to Println() followed by a call to os.Exit(1).
func Fatalln(v ...interface{}) {
	log.Fatalln(v...)
}

// Flags returns the output flags for the standard logger. The flag bits are Ldate, Ltime, and so on.
func Flags() int {
	return log.Flags()
}

// Output writes the output for a logging event. The string s contains the text to print after the
// prefix specified by the flags of the Logger. A newline is appended if the last character of s is
// not already a newline. Calldepth is the count of the number of frames to skip when computing the
// file name and line number if Llongfile or Lshortfile is set; a value of 1 will print the details
// for the caller of Output.
func Output(calldepth int, s string) error {
	return log.Output(calldepth, s)
}

// Panic is equivalent to Print() followed by a call to panic().
func Panic(v ...interface{}) {
	log.Panic(v...)
}

// Panicf is equivalent to Printf() followed by a call to panic().
func Panicf(format string, v ...interface{}) {
	log.Panicf(format, v...)
}

// Panicln is equivalent to Println() followed by a call to panic().
func Panicln(v ...interface{}) {
	log.Panicln(v...)
}

// Prefix returns the output prefix for the standard logger.
func Prefix() string {
	return log.Prefix()
}

// Print calls Output to print to the standard logger. Arguments are handled in the manner of fmt.Print.
func Print(v ...interface{}) {
	log.Print(v...)
}

// Printf calls Output to print to the standard logger. Arguments are handled in the manner of fmt.Printf.
func Printf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

// Println calls Output to print to the standard logger. Arguments are handled in the manner of fmt.Println.
func Println(v ...interface{}) {
	log.Println(v...)
}

// SetFlags sets the output flags for the standard logger. The flag bits are Ldate, Ltime, and so on.
func SetFlags(flag int) {
	log.SetFlags(flag)
}

// SetOutput sets the output destination for the standard logger.
func SetOutput(w io.Writer) {
	log.SetOutput(w)
}

// SetPrefix sets the output prefix for the standard logger.
func SetPrefix(prefix string) {
	log.SetPrefix(prefix)
}

// Writer returns the output destination for the standard logger.
func Writer() io.Writer {
	return log.Writer()
}

// Trace provides the most verbose logging - wraps Print
func Trace(v ...interface{}) {
	if level <= TraceLevel {
		log.Print(v...)
	}
}

// Traceln provides the most verbose logging - wraps Println
func Traceln(v ...interface{}) {
	if level <= TraceLevel {
		log.Println(v...)
	}
}

// Tracef provides the most verbose logging - wraps Printf
func Tracef(format string, v ...interface{}) {
	if level <= TraceLevel {
		log.Printf(format, v...)
	}
}

// Debug provides verbose logging beyond regular function - wraps Print
func Debug(v ...interface{}) {
	if level <= DebugLevel {
		log.Print(v...)
	}
}

// Debugln provides verbose logging beyond regular function - wraps Println
func Debugln(v ...interface{}) {
	if level <= DebugLevel {
		log.Println(v...)
	}
}

// Debugf provides verbose logging beyond regular function - wraps Printf
func Debugf(format string, v ...interface{}) {
	if level <= DebugLevel {
		log.Printf(format, v...)
	}
}

// Warn provides slightly more verbose logging - wraps Print
func Warn(v ...interface{}) {
	if level <= WarnLevel {
		log.Print(v...)
	}
}

// Warnln provides slightly more verbose logging- wraps Println
func Warnln(v ...interface{}) {
	if level <= WarnLevel {
		log.Println(v...)
	}
}

// Warnf provides slightly more verbose logging - wraps Printf
func Warnf(format string, v ...interface{}) {
	if level <= WarnLevel {
		log.Printf(format, v...)
	}
}

// Error provides a "normal production" logging level - wraps Print
func Error(v ...interface{}) {
	if level <= ErrorLevel {
		log.Print(v...)
	}
}

// Errorln provides a "normal production" logging level - wraps Println
func Errorln(v ...interface{}) {
	if level <= ErrorLevel {
		log.Println(v...)
	}
}

// Errorf provides a "normal production" logging level - wraps Printf
func Errorf(format string, v ...interface{}) {
	if level <= ErrorLevel {
		log.Printf(format, v...)
	}
}

// Info provides only informational logging that would typically be written to stdout - wraps Print
func Info(v ...interface{}) {
	if level <= InfoLevel {
		log.Print(v...)
	}
}

// Infoln  provides only informational logging that would typically be written to stdout - wraps Println
func Infoln(v ...interface{}) {
	if level <= InfoLevel {
		log.Println(v...)
	}
}

// Infof  provides only informational logging that would typically be written to stdout - wraps Printf
func Infof(format string, v ...interface{}) {
	if level <= InfoLevel {
		log.Printf(format, v...)
	}
}

// Logger wraps the default golang log package Logger struct so that we can still
// use its functionality and formatting while adding Log Level controls
type Logger struct {
	*log.Logger
	level Level
}

// New returns a new logger struct.
func New(out io.Writer, prefix string, flag int) *Logger {
	return &Logger{Logger: log.New(out, prefix, flag), level: level}
}

// SetLevel Sets the log level for the log package function calls,
func (l *Logger) SetLevel(ll Level) {
	l.level = ll
}

// Trace provides the most verbose logging - wraps Print
func (l *Logger) Trace(v ...interface{}) {
	if l.level <= TraceLevel {
		l.Print(v...)
	}
}

// Traceln provides the most verbose logging - wraps Println
func (l *Logger) Traceln(v ...interface{}) {
	if l.level <= TraceLevel {
		l.Println(v...)
	}
}

// Tracef provides the most verbose logging - wraps Printf
func (l *Logger) Tracef(format string, v ...interface{}) {
	if l.level <= TraceLevel {
		l.Printf(format, v...)
	}
}

// Debug provides verbose logging beyond regular function - wraps Print
func (l *Logger) Debug(v ...interface{}) {
	if l.level <= DebugLevel {
		l.Print(v...)
	}
}

// Debugln provides verbose logging beyond regular function - wraps Println
func (l *Logger) Debugln(v ...interface{}) {
	if l.level <= DebugLevel {
		l.Println(v...)
	}
}

// Debugf provides verbose logging beyond regular function - wraps Printf
func (l *Logger) Debugf(format string, v ...interface{}) {
	if l.level <= DebugLevel {
		l.Printf(format, v...)
	}
}

// Warn provides slightly more verbose logging - wraps Print
func (l *Logger) Warn(v ...interface{}) {
	if l.level <= WarnLevel {
		l.Print(v...)
	}
}

// Warnln provides slightly more verbose logging- wraps Println
func (l *Logger) Warnln(v ...interface{}) {
	if l.level <= WarnLevel {
		l.Println(v...)
	}
}

// Warnf provides slightly more verbose logging - wraps Printf
func (l *Logger) Warnf(format string, v ...interface{}) {
	if l.level <= WarnLevel {
		l.Printf(format, v...)
	}
}

// Error provides a "normal production" logging level - wraps Print
func (l *Logger) Error(v ...interface{}) {
	if l.level <= ErrorLevel {
		l.Print(v...)
	}
}

// Errorln provides a "normal production" logging level - wraps Println
func (l *Logger) Errorln(v ...interface{}) {
	if l.level <= ErrorLevel {
		l.Println(v...)
	}
}

// Errorf provides a "normal production" logging level - wraps Printf
func (l *Logger) Errorf(format string, v ...interface{}) {
	if l.level <= ErrorLevel {
		l.Printf(format, v...)
	}
}

// Info provides only informational logging that would typically be written to stdout - wraps Print
func (l *Logger) Info(v ...interface{}) {
	if l.level <= InfoLevel {
		l.Print(v...)
	}
}

// Infoln  provides only informational logging that would typically be written to stdout - wraps Println
func (l *Logger) Infoln(v ...interface{}) {
	if l.level <= InfoLevel {
		l.Println(v...)
	}
}

// Infof  provides only informational logging that would typically be written to stdout - wraps Printf
func (l *Logger) Infof(format string, v ...interface{}) {
	if l.level <= InfoLevel {
		l.Printf(format, v...)
	}
}
