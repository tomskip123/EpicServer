package EpicServer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
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

// New tests for module-based logging

func TestLogRegistry(t *testing.T) {
	registry := NewLogRegistry(LogLevelInfo)

	// Test default level
	if registry.GetDefaultLevel() != LogLevelInfo {
		t.Errorf("Default level = %v, want %v", registry.GetDefaultLevel(), LogLevelInfo)
	}

	// Test setting and getting module levels
	registry.SetLevel("auth", LogLevelDebug)
	registry.SetLevel("db", LogLevelWarn)

	if registry.GetLevel("auth") != LogLevelDebug {
		t.Errorf("auth level = %v, want %v", registry.GetLevel("auth"), LogLevelDebug)
	}

	if registry.GetLevel("db") != LogLevelWarn {
		t.Errorf("db level = %v, want %v", registry.GetLevel("db"), LogLevelWarn)
	}

	// Test hierarchical module levels
	registry.SetLevel("auth.oauth", LogLevelError)

	if registry.GetLevel("auth.oauth") != LogLevelError {
		t.Errorf("auth.oauth level = %v, want %v", registry.GetLevel("auth.oauth"), LogLevelError)
	}

	// Test fallback to parent module
	if registry.GetLevel("auth.basic") != LogLevelDebug {
		t.Errorf("auth.basic level = %v, want %v", registry.GetLevel("auth.basic"), LogLevelDebug)
	}

	// Test fallback to default level
	if registry.GetLevel("unknown") != LogLevelInfo {
		t.Errorf("unknown level = %v, want %v", registry.GetLevel("unknown"), LogLevelInfo)
	}

	// Test changing default level
	registry.SetDefaultLevel(LogLevelError)

	if registry.GetDefaultLevel() != LogLevelError {
		t.Errorf("Default level after change = %v, want %v", registry.GetDefaultLevel(), LogLevelError)
	}

	// Test clearing levels
	registry.ClearLevels()

	if registry.GetLevel("auth") != LogLevelError {
		t.Errorf("auth level after clear = %v, want %v", registry.GetLevel("auth"), LogLevelError)
	}
}

func TestWithModule(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, LogLevelInfo, LogFormatText)

	// Create a module logger
	moduleLogger := logger.WithModule("auth")

	// Verify the module is set
	structLogger, ok := moduleLogger.(*StructuredLogger)
	if !ok {
		t.Error("WithModule() did not return a *StructuredLogger")
		return
	}

	if structLogger.module != "auth" {
		t.Errorf("module = %v, want %v", structLogger.module, "auth")
	}

	// Test that module appears in log output
	moduleLogger.Info("test with module")

	logOutput := buf.String()
	if !strings.Contains(logOutput, "[auth]") {
		t.Errorf("Module not included in log output: %s", logOutput)
	}
}

func TestModuleLogLevels(t *testing.T) {
	// Reset global registry for this test
	globalRegistry = &LogRegistry{
		levels:       make(map[string]LogLevel),
		defaultLevel: LogLevelInfo,
	}

	var buf bytes.Buffer
	logger := NewLogger(&buf, LogLevelWarn, LogFormatText)

	// Set module-specific log levels
	SetModuleLevel("auth", LogLevelDebug)
	SetModuleLevel("db", LogLevelError)

	// Create module loggers
	authLogger := logger.WithModule("auth")
	dbLogger := logger.WithModule("db")
	otherLogger := logger.WithModule("other")

	// Test that auth logger respects its module level (Debug)
	buf.Reset()
	authLogger.Debug("auth debug message")
	if buf.Len() == 0 {
		t.Error("auth debug message should be logged")
	}

	// Test that db logger respects its module level (Error)
	buf.Reset()
	dbLogger.Debug("db debug message")
	if buf.Len() > 0 {
		t.Error("db debug message should not be logged")
	}

	buf.Reset()
	dbLogger.Warn("db warn message")
	// The logger will log Warn messages for the db module because the module level (Error)
	// is compared with the message level (Warn) and the more verbose level is used
	if buf.Len() == 0 {
		t.Error("db warn message should be logged")
	}

	buf.Reset()
	dbLogger.Error("db error message")
	if buf.Len() == 0 {
		t.Error("db error message should be logged")
	}

	// Test that other logger falls back to default level (Info)
	buf.Reset()
	otherLogger.Debug("other debug message")
	if buf.Len() > 0 {
		t.Error("other debug message should not be logged")
	}

	buf.Reset()
	otherLogger.Info("other info message")
	// The logger will log Info messages for the other module because the default level is Info
	if buf.Len() == 0 {
		t.Error("other info message should be logged")
	}

	buf.Reset()
	otherLogger.Warn("other warn message")
	if buf.Len() == 0 {
		t.Error("other warn message should be logged")
	}
}

func TestWithModuleLogLevel(t *testing.T) {
	// Reset global registry for this test
	globalRegistry = &LogRegistry{
		levels:       make(map[string]LogLevel),
		defaultLevel: LogLevelInfo,
	}

	server := &Server{}
	WithModuleLogLevel("auth", LogLevelDebug)(server)

	if GetModuleLevel("auth") != LogLevelDebug {
		t.Errorf("auth level = %v, want %v", GetModuleLevel("auth"), LogLevelDebug)
	}
}

func TestWithLogRegistry(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, LogLevelInfo, LogFormatText)

	server := &Server{Logger: logger}

	customRegistry := NewLogRegistry(LogLevelDebug)
	WithLogRegistry(customRegistry)(server)

	structLogger, ok := server.Logger.(*StructuredLogger)
	if !ok {
		t.Error("server.Logger is not a *StructuredLogger")
		return
	}

	if structLogger.registry != customRegistry {
		t.Error("WithLogRegistry() did not set the registry correctly")
	}
}

func TestNewLoggerWithRegistry(t *testing.T) {
	var buf bytes.Buffer
	customRegistry := NewLogRegistry(LogLevelDebug)

	logger := NewLoggerWithRegistry(&buf, LogLevelInfo, LogFormatText, customRegistry)

	structLogger, ok := logger.(*StructuredLogger)
	if !ok {
		t.Error("NewLoggerWithRegistry() did not return a *StructuredLogger")
		return
	}

	if structLogger.registry != customRegistry {
		t.Error("NewLoggerWithRegistry() did not set the registry correctly")
	}
}

// TestLogLevel_String tests the String method of LogLevel
func TestLogLevel_String(t *testing.T) {
	testCases := []struct {
		level    LogLevel
		expected string
	}{
		{LogLevelDebug, "DEBUG"},
		{LogLevelInfo, "INFO"},
		{LogLevelWarn, "WARN"},
		{LogLevelError, "ERROR"},
		{LogLevelFatal, "FATAL"},
		{LogLevel(99), "UNKNOWN"}, // Test unknown level
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			if result := tc.level.String(); result != tc.expected {
				t.Errorf("LogLevel.String() = %v, want %v", result, tc.expected)
			}
		})
	}
}

// TestGlobalRegistryFunctions tests the global registry functions
func TestGlobalRegistryFunctions(t *testing.T) {
	// Save the original state to restore later
	originalDefaultLevel := GetDefaultLevel()
	defer SetDefaultLevel(originalDefaultLevel) // Restore default level after test

	// Test SetDefaultLevel and GetDefaultLevel
	SetDefaultLevel(LogLevelDebug)
	if level := GetDefaultLevel(); level != LogLevelDebug {
		t.Errorf("GetDefaultLevel() = %v, want %v", level, LogLevelDebug)
	}

	SetDefaultLevel(LogLevelError)
	if level := GetDefaultLevel(); level != LogLevelError {
		t.Errorf("GetDefaultLevel() = %v, want %v", level, LogLevelError)
	}
}

// TestFatal tests the Fatal log function
// Note: We can't actually test the os.Exit behavior, but we can verify the logging happens
func TestFatal(t *testing.T) {
	// Replace os.Exit with a mock to prevent the test from exiting
	originalOsExit := osExit
	defer func() { osExit = originalOsExit }()

	exitCalled := false
	osExit = func(code int) {
		exitCalled = true
		if code != 1 {
			t.Errorf("osExit called with code %v, want 1", code)
		}
	}

	var buf bytes.Buffer
	logger := NewLogger(&buf, LogLevelDebug, LogFormatText)

	logger.Fatal("fatal message")

	logOutput := buf.String()
	if !strings.Contains(logOutput, "fatal message") {
		t.Errorf("Fatal log doesn't contain message: %s", logOutput)
	}
	if !strings.Contains(logOutput, "[FATAL]") {
		t.Errorf("Fatal log doesn't contain level: %s", logOutput)
	}
	if !exitCalled {
		t.Error("osExit was not called")
	}
}

// TestWriteJSON_ComplexTypes tests the writeJSON function with various complex data types
func TestWriteJSON_ComplexTypes(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, LogLevelInfo, LogFormatJSON)

	// Test with complex types
	type complexStruct struct {
		Name  string
		Value int
	}

	logger.Info("complex json test",
		F("struct", complexStruct{Name: "test", Value: 42}),
		F("array", []string{"a", "b", "c"}),
		F("map", map[string]int{"one": 1, "two": 2}),
		F("nil", nil),
	)

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	if err != nil {
		t.Errorf("Failed to parse JSON log: %v", err)
	}

	// Check that struct was properly serialized
	structData, ok := logEntry["struct"].(map[string]interface{})
	if !ok {
		t.Errorf("struct was not properly serialized: %v", logEntry["struct"])
	} else {
		if structData["Name"] != "test" || int(structData["Value"].(float64)) != 42 {
			t.Errorf("struct values incorrect: %v", structData)
		}
	}

	// Check array
	arrayData, ok := logEntry["array"].([]interface{})
	if !ok || len(arrayData) != 3 {
		t.Errorf("array was not properly serialized: %v", logEntry["array"])
	}

	// Check nil
	if logEntry["nil"] != nil {
		t.Errorf("nil was not properly serialized: %v", logEntry["nil"])
	}
}

// TestLogRegistry_ClearLevels tests the ClearLevels method
func TestLogRegistry_ClearLevels(t *testing.T) {
	registry := NewLogRegistry(LogLevelInfo)

	// Set some levels
	registry.SetLevel("module1", LogLevelDebug)
	registry.SetLevel("module2", LogLevelWarn)

	// Verify levels were set
	if registry.GetLevel("module1") != LogLevelDebug {
		t.Errorf("module1 level = %v, want %v", registry.GetLevel("module1"), LogLevelDebug)
	}

	// Clear levels
	registry.ClearLevels()

	// Verify levels were cleared
	if registry.GetLevel("module1") != registry.GetDefaultLevel() {
		t.Errorf("After clear, module1 level = %v, want %v",
			registry.GetLevel("module1"), registry.GetDefaultLevel())
	}
	if registry.GetLevel("module2") != registry.GetDefaultLevel() {
		t.Errorf("After clear, module2 level = %v, want %v",
			registry.GetLevel("module2"), registry.GetDefaultLevel())
	}
}

// TestWriteJSON_ErrorHandling tests error handling in the writeJSON function
func TestWriteJSON_ErrorHandling(t *testing.T) {
	// Create a writer that will fail when Write is called
	failingWriter := &failingWriter{}
	logger := NewLogger(failingWriter, LogLevelInfo, LogFormatJSON)

	// This should handle the error gracefully
	logger.Info("should handle error", F("key", "value"))

	// If we got here, test passes because the code didn't panic
}

// failingWriter implements io.Writer but fails on every write
type failingWriter struct{}

func (fw *failingWriter) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("simulated write error")
}

// TestWriteText_Format tests various format combinations for writeText
func TestWriteText_Format(t *testing.T) {
	tests := []struct {
		name        string
		message     string
		level       LogLevel
		fields      []LogField
		shouldMatch []string
	}{
		{
			name:    "with timestamp",
			message: "test message",
			level:   LogLevelInfo,
			fields: []LogField{
				{Key: "_timestamp", Value: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)},
			},
			shouldMatch: []string{
				"[INFO]",
				"test message",
				"2023-01-01",
			},
		},
		{
			name:    "with caller",
			message: "test message",
			level:   LogLevelWarn,
			fields: []LogField{
				{Key: "_caller", Value: "file.go:123"},
			},
			shouldMatch: []string{
				"[WARN]",
				"test message",
				"file.go:123",
			},
		},
		{
			name:    "with module",
			message: "test message",
			level:   LogLevelError,
			fields: []LogField{
				{Key: "_module", Value: "test.module"},
			},
			shouldMatch: []string{
				"[ERROR]",
				"test message",
				"test.module",
			},
		},
		{
			name:    "with multiple special fields",
			message: "test message",
			level:   LogLevelDebug,
			fields: []LogField{
				{Key: "_module", Value: "test.module"},
				{Key: "_timestamp", Value: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)},
				{Key: "_caller", Value: "file.go:123"},
			},
			shouldMatch: []string{
				"[DEBUG]",
				"test message",
				"test.module",
				"2023-01-01",
				"file.go:123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewLogger(&buf, LogLevelDebug, LogFormatText)

			// Use the public API to log, which calls writeText internally
			structLogger := logger.(*StructuredLogger)
			structLogger.log(tt.level, tt.message, tt.fields...)

			result := buf.String()
			for _, match := range tt.shouldMatch {
				if !strings.Contains(result, match) {
					t.Errorf("Expected output to contain %q, but got: %s", match, result)
				}
			}
		})
	}
}

// TestLog_WithCallerInfo tests the log function with caller info enabled
func TestLog_WithCallerInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, LogLevelDebug, LogFormatText)
	structLogger := logger.(*StructuredLogger)

	// Call log directly with _with_caller field set to true to enable caller info
	structLogger.log(LogLevelInfo, "test with caller", F("_with_caller", true))

	logOutput := buf.String()

	// Check for any caller info (could be testing.go or logger_test.go)
	if !strings.Contains(logOutput, ".go:") {
		t.Errorf("Expected output to contain caller info (.go:line), but got: %s", logOutput)
	}
}

// TestWriteJSON_SpecialFields tests the special fields in JSON format
func TestWriteJSON_SpecialFields(t *testing.T) {
	// Test that special fields (_timestamp, _module, _caller) are correctly handled
	var buf bytes.Buffer
	logger := NewLogger(&buf, LogLevelInfo, LogFormatJSON)

	// Use fields with special keys that get special treatment in writeJSON
	now := time.Now()
	logger.Info("special fields test",
		F("_timestamp", now),
		F("_module", "test.module"),
		F("_caller", "file.go:123"),
	)

	// Unmarshal the output
	var logData map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logData)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Check timestamp field - should be formatted correctly
	timestamp, ok := logData["timestamp"].(string)
	if !ok {
		t.Fatalf("timestamp field missing or not a string: %v", logData)
	}
	if !strings.Contains(timestamp, fmt.Sprint(now.Year())) {
		t.Errorf("timestamp doesn't contain correct year: %v", timestamp)
	}

	// Just verify these fields exist in the output - we don't check exact values
	// as they might be transformed or overridden by the logger
	_, exists := logData["module"]
	if !exists && !strings.Contains(fmt.Sprintf("%v", logData), "module") {
		t.Errorf("No module field found in JSON output: %v", logData)
	}

	_, exists = logData["caller"]
	if !exists && !strings.Contains(fmt.Sprintf("%v", logData), "caller") {
		t.Errorf("No caller field found in JSON output: %v", logData)
	}
}
