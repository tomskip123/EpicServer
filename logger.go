package EpicServer

import (
	"io"
	"log"
)

type Logger interface {
	Debug(args ...interface{})
	Info(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
}

// setting up the default App logger
type AppLogger struct {
	logger *log.Logger
}

func defaultLogger(output io.Writer) *AppLogger {
	return &AppLogger{
		logger: log.New(output, "", log.LstdFlags),
	}
}

func (l *AppLogger) Debug(args ...interface{}) {
	l.logger.Println(append([]interface{}{"[DEBUG]"}, args...)...)
}

func (l *AppLogger) Info(args ...interface{}) {
	l.logger.Println(append([]interface{}{"[INFO]"}, args...)...)
}

func (l *AppLogger) Warn(args ...interface{}) {
	l.logger.Println(append([]interface{}{"[WARN]"}, args...)...)
}

func (l *AppLogger) Error(args ...interface{}) {
	l.logger.Println(append([]interface{}{"[ERROR]"}, args...)...)
}
