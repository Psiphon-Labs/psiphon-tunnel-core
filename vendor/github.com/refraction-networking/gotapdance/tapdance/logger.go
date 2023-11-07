package tapdance

import (
	"fmt"
	"io"
	"sync"

	"github.com/sirupsen/logrus"
)

// implements interface logrus.Formatter
type formatter struct {
}

func (f *formatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(fmt.Sprintf("[%s] %s\n", entry.Time.Format("15:04:05"), entry.Message)), nil
}

var logrusLogger *logrus.Logger
var initLoggerOnce sync.Once

// Logger is an access point for TapDance-wide logger
func Logger() *logrus.Logger {
	initLoggerOnce.Do(func() {
		logrusLogger = logrus.New()
		logrusLogger.Formatter = new(formatter)
		// logrusLogger.Level = logrus.InfoLevel
		logrusLogger.Level = logrus.DebugLevel

		// buildInfo const will be overwritten by CI with `sed` for test builds
		// if not overwritten -- this is a NO-OP
		const buildInfo = ""
		if len(buildInfo) > 0 {
			logrusLogger.Infof("Running gotapdance build %s", buildInfo)
		}
	})
	return logrusLogger
}

// SetLoggerOutput will allow a caller to change the Logger output from the
// default of os.Stderr
func SetLoggerOutput(out io.Writer) {
	Logger().SetOutput(out)
}
