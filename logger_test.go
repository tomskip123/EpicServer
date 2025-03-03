package EpicServer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDefaultLogger(t *testing.T) {
	logger := defaultLogger(nil)
	if logger == nil {
		t.Error("defaultLogger() returned nil")
	}
}

func TestLogger_Levels(t *testing.T) {
	var buf bytes.Buffer

	logger := defaultLogger(&buf)
	// Set log level to Debug to allow all log levels
	if structLogger, ok := logger.(*StructuredLogger); ok {
		structLogger.SetLevel(LogLevelDebug)
	}

	tests := []struct {
		name     string
		logFunc  func(msg string, fields ...LogField)
		message  string
		wantText string
	}{
		{
			name:     "info level",
			logFunc:  logger.Info,
			message:  "test info",
			wantText: "[INFO] test info",
		},
		{
			name:     "error level",
			logFunc:  logger.Error,
			message:  "test error",
			wantText: "[ERROR] test error",
		},
		{
			name:     "debug level",
			logFunc:  logger.Debug,
			message:  "test debug",
			wantText: "[DEBUG] test debug",
		},
		{
			name:     "warn level",
			logFunc:  logger.Warn,
			message:  "test warn",
			wantText: "[WARN] test warn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc(tt.message)

			if !bytes.Contains(buf.Bytes(), []byte(tt.wantText)) {
				t.Errorf("logger output = %q, want %q", buf.String(), tt.wantText)
			}
		})
	}
}

// New tests for untested functions

func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, LogLevelInfo, LogFormatText)

	if logger == nil {
		t.Error("NewLogger() returned nil")
	}

	// Verify level setting worked
	structLogger, ok := logger.(*StructuredLogger)
	if !ok {
		t.Error("NewLogger() did not return a *StructuredLogger")
		return
	}

	if structLogger.level != LogLevelInfo {
		t.Errorf("logger level = %v, want %v", structLogger.level, LogLevelInfo)
	}

	if structLogger.format != LogFormatText {
		t.Errorf("logger format = %v, want %v", structLogger.format, LogFormatText)
	}

	if structLogger.writer != &buf {
		t.Error("logger writer not set correctly")
	}
}

func TestSetOutput(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	logger := NewLogger(&buf1, LogLevelInfo, LogFormatText)

	structLogger, ok := logger.(*StructuredLogger)
	if !ok {
		t.Error("NewLogger() did not return a *StructuredLogger")
		return
	}

	logger.SetOutput(&buf2)

	if structLogger.writer != &buf2 {
		t.Error("SetOutput() did not change the writer")
	}
}

func TestSetFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, LogLevelInfo, LogFormatText)

	logger.SetFormat(LogFormatJSON)
	logger.Info("test message")

	// Verify JSON format was used
	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	if err != nil {
		t.Errorf("Failed to parse JSON log: %v", err)
	}

	if logEntry["message"] != "test message" {
		t.Errorf("JSON log message = %v, want 'test message'", logEntry["message"])
	}

	if logEntry["level"] != "INFO" {
		t.Errorf("JSON log level = %v, want 'INFO'", logEntry["level"])
	}
}

func TestLoggerWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, LogLevelInfo, LogFormatText)

	fieldLogger := logger.WithFields(F("user", "test"), F("request_id", "123"))
	fieldLogger.Info("test with fields")

	logOutput := buf.String()

	if !strings.Contains(logOutput, "user=test") {
		t.Errorf("WithFields() did not include 'user=test' field: %s", logOutput)
	}

	if !strings.Contains(logOutput, "request_id=123") {
		t.Errorf("WithFields() did not include 'request_id=123' field: %s", logOutput)
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, LogLevelInfo, LogFormatJSON)

	logger.Info("json test", F("key1", "value1"), F("key2", 42))

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	if err != nil {
		t.Errorf("Failed to parse JSON log: %v", err)
	}

	if logEntry["message"] != "json test" {
		t.Errorf("JSON log message = %v, want 'json test'", logEntry["message"])
	}

	if logEntry["key1"] != "value1" {
		t.Errorf("JSON log field key1 = %v, want 'value1'", logEntry["key1"])
	}

	if int(logEntry["key2"].(float64)) != 42 {
		t.Errorf("JSON log field key2 = %v, want 42", logEntry["key2"])
	}
}

// Test for server app layers
func TestWithCustomLogger(t *testing.T) {
	var buf bytes.Buffer
	customLogger := NewLogger(&buf, LogLevelDebug, LogFormatJSON)

	server := &Server{}
	WithCustomLogger(customLogger)(server)

	if server.Logger != customLogger {
		t.Error("WithCustomLogger() did not set the logger correctly")
	}
}

func TestWithLogLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, LogLevelInfo, LogFormatText)

	server := &Server{Logger: logger}
	WithLogLevel(LogLevelDebug)(server)

	structLogger, ok := server.Logger.(*StructuredLogger)
	if !ok {
		t.Error("server.Logger is not a *StructuredLogger")
		return
	}

	if structLogger.level != LogLevelDebug {
		t.Errorf("WithLogLevel() set level to %v, want %v", structLogger.level, LogLevelDebug)
	}
}

func TestWithLogFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, LogLevelInfo, LogFormatText)

	server := &Server{Logger: logger}
	WithLogFormat(LogFormatJSON)(server)

	structLogger, ok := server.Logger.(*StructuredLogger)
	if !ok {
		t.Error("server.Logger is not a *StructuredLogger")
		return
	}

	if structLogger.format != LogFormatJSON {
		t.Errorf("WithLogFormat() set format to %v, want %v", structLogger.format, LogFormatJSON)
	}
}
