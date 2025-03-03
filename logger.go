package EpicServer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel int

const (
	// LogLevelDebug is the most verbose logging level
	LogLevelDebug LogLevel = iota
	// LogLevelInfo is for general operational information
	LogLevelInfo
	// LogLevelWarn is for warning conditions
	LogLevelWarn
	// LogLevelError is for error conditions
	LogLevelError
	// LogLevelFatal is for fatal conditions that should stop the application
	LogLevelFatal
)

// String returns the string representation of a log level
func (l LogLevel) String() string {
	switch l {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	case LogLevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// LogFormat defines how logs are formatted
type LogFormat int

const (
	// LogFormatText outputs logs in a human-readable text format
	LogFormatText LogFormat = iota
	// LogFormatJSON outputs logs in JSON format for machine processing
	LogFormatJSON
)

// Logger is an interface for logging messages
type Logger interface {
	Debug(msg string, fields ...LogField)
	Info(msg string, fields ...LogField)
	Warn(msg string, fields ...LogField)
	Error(msg string, fields ...LogField)
	Fatal(msg string, fields ...LogField)
	WithFields(fields ...LogField) Logger
	SetOutput(w io.Writer)
	SetLevel(level LogLevel)
	SetFormat(format LogFormat)
}

// LogField represents a key-value pair in a structured log
type LogField struct {
	Key   string
	Value interface{}
}

// F creates a new log field
func F(key string, value interface{}) LogField {
	return LogField{Key: key, Value: value}
}

// StructuredLogger implements the Logger interface
type StructuredLogger struct {
	mu     sync.Mutex
	writer io.Writer
	level  LogLevel
	format LogFormat
	fields []LogField
}

// defaultLogger creates a new default logger
func defaultLogger(w io.Writer) Logger {
	return &StructuredLogger{
		writer: w,
		level:  LogLevelInfo,
		format: LogFormatText,
		fields: []LogField{},
	}
}

// NewLogger creates a new structured logger
func NewLogger(w io.Writer, level LogLevel, format LogFormat) Logger {
	return &StructuredLogger{
		writer: w,
		level:  level,
		format: format,
		fields: []LogField{},
	}
}

// SetOutput sets the output writer
func (l *StructuredLogger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writer = w
}

// SetLevel sets the minimum log level
func (l *StructuredLogger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetFormat sets the log format
func (l *StructuredLogger) SetFormat(format LogFormat) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.format = format
}

// WithFields returns a new logger with the given fields
func (l *StructuredLogger) WithFields(fields ...LogField) Logger {
	newLogger := &StructuredLogger{
		writer: l.writer,
		level:  l.level,
		format: l.format,
		fields: make([]LogField, len(l.fields)+len(fields)),
	}

	copy(newLogger.fields, l.fields)
	copy(newLogger.fields[len(l.fields):], fields)

	return newLogger
}

// Debug logs a debug message
func (l *StructuredLogger) Debug(msg string, fields ...LogField) {
	if l.level <= LogLevelDebug {
		l.log(LogLevelDebug, msg, fields...)
	}
}

// Info logs an info message
func (l *StructuredLogger) Info(msg string, fields ...LogField) {
	if l.level <= LogLevelInfo {
		l.log(LogLevelInfo, msg, fields...)
	}
}

// Warn logs a warning message
func (l *StructuredLogger) Warn(msg string, fields ...LogField) {
	if l.level <= LogLevelWarn {
		l.log(LogLevelWarn, msg, fields...)
	}
}

// Error logs an error message
func (l *StructuredLogger) Error(msg string, fields ...LogField) {
	if l.level <= LogLevelError {
		l.log(LogLevelError, msg, fields...)
	}
}

// Fatal logs a fatal message
func (l *StructuredLogger) Fatal(msg string, fields ...LogField) {
	if l.level <= LogLevelFatal {
		l.log(LogLevelFatal, msg, fields...)
		os.Exit(1)
	}
}

// log handles the actual logging
func (l *StructuredLogger) log(level LogLevel, msg string, fields ...LogField) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Get caller information
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		file = "unknown"
		line = 0
	}

	// Simplify file path by only including the last 2 directories
	parts := strings.Split(file, "/")
	if len(parts) > 2 {
		file = strings.Join(parts[len(parts)-2:], "/")
	}

	now := time.Now().Format(time.RFC3339)

	// Combine all fields
	allFields := make([]LogField, 0, len(l.fields)+len(fields)+4)
	allFields = append(allFields, l.fields...)
	allFields = append(allFields, fields...)
	allFields = append(allFields,
		LogField{Key: "timestamp", Value: now},
		LogField{Key: "level", Value: level.String()},
		LogField{Key: "message", Value: msg},
		LogField{Key: "caller", Value: fmt.Sprintf("%s:%d", file, line)},
	)

	if l.format == LogFormatJSON {
		l.writeJSON(allFields)
	} else {
		l.writeText(level, msg, allFields)
	}
}

// writeJSON writes the log as JSON
func (l *StructuredLogger) writeJSON(fields []LogField) {
	data := make(map[string]interface{})
	for _, field := range fields {
		data[field.Key] = field.Value
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling log: %v\n", err)
		return
	}

	bytes = append(bytes, '\n')
	_, err = l.writer.Write(bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing log: %v\n", err)
	}
}

// writeText writes the log in a human-readable format
func (l *StructuredLogger) writeText(level LogLevel, msg string, fields []LogField) {
	// Extract timestamp and caller from fields
	var timestamp, caller string
	fieldsMap := make(map[string]interface{})

	for _, field := range fields {
		fieldsMap[field.Key] = field.Value
		if field.Key == "timestamp" {
			if ts, ok := field.Value.(string); ok {
				timestamp = ts
			}
		} else if field.Key == "caller" {
			if c, ok := field.Value.(string); ok {
				caller = c
			}
		}
	}

	// Format the log entry
	var sb strings.Builder

	// Format timestamp, level, and message
	fmt.Fprintf(&sb, "%s [%s] %-44s %s", timestamp, level, msg, caller)

	// Add remaining fields
	if len(fieldsMap) > 0 {
		sb.WriteString(" |")
		for _, field := range fields {
			if field.Key != "timestamp" && field.Key != "level" && field.Key != "message" && field.Key != "caller" {
				fmt.Fprintf(&sb, " %s=%v", field.Key, field.Value)
			}
		}
	}

	sb.WriteString("\n")

	_, err := l.writer.Write([]byte(sb.String()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing log: %v\n", err)
	}
}

// WithCustomLogger adds a custom logger to the server
func WithCustomLogger(logger Logger) AppLayer {
	return func(s *Server) {
		s.Logger = logger
	}
}

// WithLogLevel sets the log level for the server's logger
func WithLogLevel(level LogLevel) AppLayer {
	return func(s *Server) {
		if logger, ok := s.Logger.(*StructuredLogger); ok {
			logger.SetLevel(level)
		}
	}
}

// WithLogFormat sets the log format for the server's logger
func WithLogFormat(format LogFormat) AppLayer {
	return func(s *Server) {
		if logger, ok := s.Logger.(*StructuredLogger); ok {
			logger.SetFormat(format)
		}
	}
}
