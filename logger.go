// Package EpicServer provides a comprehensive web server framework with built-in
// logging, authentication, database connections, caching, and more.
//
// The logging system in this package offers structured logging with multiple levels,
// formats, and module-based filtering. It supports both human-readable text output
// and machine-readable JSON format.
//
// # Basic Logging Example
//
//	import (
//	    "os"
//	    "github.com/tomskip123/EpicServer/v2"
//	)
//
//	// Create a new logger
//	logger := EpicServer.NewLogger(os.Stdout, EpicServer.LogLevelInfo, EpicServer.LogFormatText)
//
//	// Log messages at different levels
//	logger.Info("Server starting", EpicServer.F("port", 8080))
//	logger.Debug("Connection details", EpicServer.F("timeout", "30s"))
//
//	// Add structured fields
//	logger = logger.WithFields(
//	    EpicServer.F("app", "myapp"),
//	    EpicServer.F("env", "production"),
//	)
//	logger.Info("Application context")
//
//	// Log for specific modules
//	authLogger := logger.WithModule("auth")
//	authLogger.Info("User authenticated", EpicServer.F("user_id", "123"))
//
// # Module-Based Logging Example
//
//	// Set log levels for specific modules
//	EpicServer.SetModuleLevel("auth", EpicServer.LogLevelDebug)
//	EpicServer.SetModuleLevel("db", EpicServer.LogLevelWarn)
//
//	// Now auth module will show debug logs, but db will only show warnings and above
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

// For testing purposes - allows mocking os.Exit
var osExit = os.Exit

// LogLevel represents the severity of a log message.
// The levels are ordered from most verbose (Debug) to least verbose (Fatal).
type LogLevel int

const (
	// LogLevelDebug is the most verbose logging level.
	// Use for detailed troubleshooting information.
	LogLevelDebug LogLevel = iota
	// LogLevelInfo is for general operational information.
	// Use for normal application behavior reporting.
	LogLevelInfo
	// LogLevelWarn is for warning conditions.
	// Use for potentially harmful situations that don't affect normal operation.
	LogLevelWarn
	// LogLevelError is for error conditions.
	// Use for errors that affect operation but don't require immediate action.
	LogLevelError
	// LogLevelFatal is for fatal conditions that should stop the application.
	// Use for severe errors that prevent the application from continuing.
	LogLevelFatal
)

// String returns the string representation of a log level.
// This is used when formatting log messages.
//
// Example:
//
//	level := EpicServer.LogLevelWarn
//	fmt.Println(level.String()) // Outputs: "WARN"
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

// LogFormat defines how logs are formatted.
// Different formats are suitable for different environments.
type LogFormat int

const (
	// LogFormatText outputs logs in a human-readable text format.
	// This is best for development and debugging.
	LogFormatText LogFormat = iota
	// LogFormatJSON outputs logs in JSON format for machine processing.
	// This is best for production environments with log aggregation systems.
	LogFormatJSON
)

// LogRegistry maintains a registry of log levels by module.
// This allows for fine-grained control over which modules log at which levels.
//
// Example:
//
//	registry := EpicServer.NewLogRegistry(EpicServer.LogLevelInfo)
//	registry.SetLevel("auth", EpicServer.LogLevelDebug)
//	registry.SetLevel("db", EpicServer.LogLevelWarn)
type LogRegistry struct {
	mu           sync.RWMutex
	levels       map[string]LogLevel
	defaultLevel LogLevel
}

// globalRegistry is the default registry for log levels
var globalRegistry = &LogRegistry{
	levels:       make(map[string]LogLevel),
	defaultLevel: LogLevelInfo,
}

// NewLogRegistry creates a new log registry with the specified default level.
// The registry allows for module-specific log level configuration.
//
// Example:
//
//	// Create a registry with Info as the default level
//	registry := EpicServer.NewLogRegistry(EpicServer.LogLevelInfo)
func NewLogRegistry(defaultLevel LogLevel) *LogRegistry {
	return &LogRegistry{
		levels:       make(map[string]LogLevel),
		defaultLevel: defaultLevel,
	}
}

// SetLevel sets the log level for a specific module.
// This allows for fine-grained control over logging verbosity.
//
// Example:
//
//	registry.SetLevel("auth", EpicServer.LogLevelDebug)
//	registry.SetLevel("db", EpicServer.LogLevelWarn)
func (r *LogRegistry) SetLevel(module string, level LogLevel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.levels[module] = level
}

// GetLevel gets the log level for a specific module.
// If no level is set for the module, it checks parent modules
// and falls back to the default level.
//
// Example:
//
//	level := registry.GetLevel("auth.oauth")
//	// If "auth.oauth" isn't set, it checks "auth", then falls back to default
func (r *LogRegistry) GetLevel(module string) LogLevel {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if level, ok := r.levels[module]; ok {
		return level
	}

	// Check for parent modules (e.g., "auth.oauth" falls back to "auth")
	parts := strings.Split(module, ".")
	for i := len(parts) - 1; i > 0; i-- {
		parentModule := strings.Join(parts[:i], ".")
		if level, ok := r.levels[parentModule]; ok {
			return level
		}
	}

	return r.defaultLevel
}

// SetDefaultLevel sets the default log level for modules without a specific level.
// This affects all modules that don't have an explicit level set.
//
// Example:
//
//	// Set default level to warn
//	registry.SetDefaultLevel(EpicServer.LogLevelWarn)
func (r *LogRegistry) SetDefaultLevel(level LogLevel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultLevel = level
}

// GetDefaultLevel gets the default log level.
// This is used for modules that don't have a specific level set.
//
// Example:
//
//	level := registry.GetDefaultLevel()
//	fmt.Println(level.String()) // Outputs the default level
func (r *LogRegistry) GetDefaultLevel() LogLevel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultLevel
}

// ClearLevels removes all module-specific log levels.
// After calling this, all modules will use the default level.
//
// Example:
//
//	// Reset all module levels to use the default
//	registry.ClearLevels()
func (r *LogRegistry) ClearLevels() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.levels = make(map[string]LogLevel)
}

// SetModuleLevel sets the log level for a specific module in the global registry.
// This is a convenience function that uses the global registry.
//
// Example:
//
//	// Set auth module to debug level
//	EpicServer.SetModuleLevel("auth", EpicServer.LogLevelDebug)
func SetModuleLevel(module string, level LogLevel) {
	globalRegistry.SetLevel(module, level)
}

// GetModuleLevel gets the log level for a specific module from the global registry.
// This is a convenience function that uses the global registry.
//
// Example:
//
//	level := EpicServer.GetModuleLevel("auth")
//	fmt.Println(level.String()) // Outputs the level for the auth module
func GetModuleLevel(module string) LogLevel {
	return globalRegistry.GetLevel(module)
}

// SetDefaultLevel sets the default log level in the global registry.
// This is a convenience function that uses the global registry.
//
// Example:
//
//	// Set default level to warn
//	EpicServer.SetDefaultLevel(EpicServer.LogLevelWarn)
func SetDefaultLevel(level LogLevel) {
	globalRegistry.SetDefaultLevel(level)
}

// GetDefaultLevel gets the default log level from the global registry.
// This is a convenience function that uses the global registry.
//
// Example:
//
//	level := EpicServer.GetDefaultLevel()
//	fmt.Println(level.String()) // Outputs the default level
func GetDefaultLevel() LogLevel {
	return globalRegistry.GetDefaultLevel()
}

// Logger is an interface for logging messages.
// It provides methods for logging at different levels and with structured fields.
//
// Example:
//
//	logger.Info("Server started", EpicServer.F("port", 8080))
//	logger.Error("Database connection failed", EpicServer.F("error", err.Error()))
type Logger interface {
	Debug(msg string, fields ...LogField)
	Info(msg string, fields ...LogField)
	Warn(msg string, fields ...LogField)
	Error(msg string, fields ...LogField)
	Fatal(msg string, fields ...LogField)
	WithFields(fields ...LogField) Logger
	WithModule(module string) Logger
	SetOutput(w io.Writer)
	SetLevel(level LogLevel)
	SetFormat(format LogFormat)
	SetRegistry(registry *LogRegistry)
}

// LogField represents a key-value pair in a structured log.
// These fields provide context to log messages.
//
// Example:
//
//	EpicServer.F("user_id", "123")
//	EpicServer.F("request_time", 235.42)
type LogField struct {
	Key   string
	Value interface{}
}

// F creates a new log field.
// This is a convenience function for creating structured log fields.
//
// Example:
//
//	logger.Info("User logged in",
//	    EpicServer.F("user_id", "123"),
//	    EpicServer.F("ip", "192.168.1.1"),
//	)
func F(key string, value interface{}) LogField {
	return LogField{Key: key, Value: value}
}

// StructuredLogger implements the Logger interface.
// It provides structured logging with support for different levels,
// formats, and module-based filtering.
type StructuredLogger struct {
	mu       sync.Mutex
	writer   io.Writer
	level    LogLevel
	format   LogFormat
	fields   []LogField
	module   string
	registry *LogRegistry
}

// defaultLogger creates a new default logger.
// This is used internally when no logger is specified.
func defaultLogger(w io.Writer) Logger {
	return &StructuredLogger{
		writer:   w,
		level:    LogLevelInfo,
		format:   LogFormatText,
		fields:   []LogField{},
		module:   "",
		registry: globalRegistry,
	}
}

// NewLogger creates a new structured logger.
// This is the main entry point for creating a logger.
//
// Example:
//
//	// Create a logger that writes to stdout, at info level, in text format
//	logger := EpicServer.NewLogger(os.Stdout, EpicServer.LogLevelInfo, EpicServer.LogFormatText)
//
//	// Log a message
//	logger.Info("Application started")
func NewLogger(w io.Writer, level LogLevel, format LogFormat) Logger {
	return &StructuredLogger{
		writer:   w,
		level:    level,
		format:   format,
		fields:   []LogField{},
		module:   "",
		registry: globalRegistry,
	}
}

// NewLoggerWithRegistry creates a new structured logger with a custom registry.
// This allows for fine-grained control over module-specific log levels.
//
// Example:
//
//	registry := EpicServer.NewLogRegistry(EpicServer.LogLevelInfo)
//	registry.SetLevel("auth", EpicServer.LogLevelDebug)
//
//	logger := EpicServer.NewLoggerWithRegistry(
//	    os.Stdout,
//	    EpicServer.LogLevelInfo,
//	    EpicServer.LogFormatText,
//	    registry,
//	)
func NewLoggerWithRegistry(w io.Writer, level LogLevel, format LogFormat, registry *LogRegistry) Logger {
	return &StructuredLogger{
		writer:   w,
		level:    level,
		format:   format,
		fields:   []LogField{},
		module:   "",
		registry: registry,
	}
}

// SetOutput sets the output writer.
// This allows changing where logs are written to.
//
// Example:
//
//	// Write logs to a file
//	file, _ := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
//	logger.SetOutput(file)
func (l *StructuredLogger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writer = w
}

// SetLevel sets the minimum log level.
// Messages below this level will not be logged.
//
// Example:
//
//	// Only log warnings and above
//	logger.SetLevel(EpicServer.LogLevelWarn)
func (l *StructuredLogger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetFormat sets the log format.
// This determines how log messages are formatted.
//
// Example:
//
//	// Use JSON format for machine processing
//	logger.SetFormat(EpicServer.LogFormatJSON)
func (l *StructuredLogger) SetFormat(format LogFormat) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.format = format
}

// SetRegistry sets the log registry.
// This allows changing the module-specific log level configuration.
//
// Example:
//
//	registry := EpicServer.NewLogRegistry(EpicServer.LogLevelInfo)
//	registry.SetLevel("auth", EpicServer.LogLevelDebug)
//	logger.SetRegistry(registry)
func (l *StructuredLogger) SetRegistry(registry *LogRegistry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.registry = registry
}

// WithFields returns a new logger with the given fields
func (l *StructuredLogger) WithFields(fields ...LogField) Logger {
	newLogger := &StructuredLogger{
		writer:   l.writer,
		level:    l.level,
		format:   l.format,
		module:   l.module,
		registry: l.registry,
		fields:   make([]LogField, len(l.fields)+len(fields)),
	}

	copy(newLogger.fields, l.fields)
	copy(newLogger.fields[len(l.fields):], fields)

	return newLogger
}

// WithModule returns a new logger with the specified module
func (l *StructuredLogger) WithModule(module string) Logger {
	newLogger := &StructuredLogger{
		writer:   l.writer,
		level:    l.level,
		format:   l.format,
		module:   module,
		registry: l.registry,
		fields:   make([]LogField, len(l.fields)),
	}

	copy(newLogger.fields, l.fields)

	return newLogger
}

// getEffectiveLevel returns the effective log level for the current module
func (l *StructuredLogger) getEffectiveLevel() LogLevel {
	if l.module == "" {
		return l.level
	}

	moduleLevel := l.registry.GetLevel(l.module)

	// Use the more verbose of the two levels
	if moduleLevel < l.level {
		return moduleLevel
	}
	return l.level
}

// Debug logs a debug message
func (l *StructuredLogger) Debug(msg string, fields ...LogField) {
	if l.getEffectiveLevel() <= LogLevelDebug {
		l.log(LogLevelDebug, msg, fields...)
	}
}

// Info logs an info message
func (l *StructuredLogger) Info(msg string, fields ...LogField) {
	if l.getEffectiveLevel() <= LogLevelInfo {
		l.log(LogLevelInfo, msg, fields...)
	}
}

// Warn logs a warning message
func (l *StructuredLogger) Warn(msg string, fields ...LogField) {
	if l.getEffectiveLevel() <= LogLevelWarn {
		l.log(LogLevelWarn, msg, fields...)
	}
}

// Error logs an error message
func (l *StructuredLogger) Error(msg string, fields ...LogField) {
	if l.getEffectiveLevel() <= LogLevelError {
		l.log(LogLevelError, msg, fields...)
	}
}

// Fatal logs a message at Fatal level and then exits the application
func (l *StructuredLogger) Fatal(msg string, fields ...LogField) {
	if l.getEffectiveLevel() <= LogLevelFatal {
		l.log(LogLevelFatal, msg, fields...)
		osExit(1)
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
	allFields := make([]LogField, 0, len(l.fields)+len(fields)+5)
	allFields = append(allFields, l.fields...)
	allFields = append(allFields, fields...)
	allFields = append(allFields,
		LogField{Key: "timestamp", Value: now},
		LogField{Key: "level", Value: level.String()},
		LogField{Key: "message", Value: msg},
		LogField{Key: "caller", Value: fmt.Sprintf("%s:%d", file, line)},
	)

	// Add module if set
	if l.module != "" {
		allFields = append(allFields, LogField{Key: "module", Value: l.module})
	}

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
	var timestamp, caller, module string
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
		} else if field.Key == "module" {
			if m, ok := field.Value.(string); ok {
				module = m
			}
		}
	}

	// Format the log message
	var builder strings.Builder

	// Add timestamp
	builder.WriteString(timestamp)
	builder.WriteString(" ")

	// Add log level
	builder.WriteString("[")
	builder.WriteString(level.String())
	builder.WriteString("] ")

	// Add module if present
	if module != "" {
		builder.WriteString("[")
		builder.WriteString(module)
		builder.WriteString("] ")
	}

	// Add message
	builder.WriteString(msg)

	// Add caller
	builder.WriteString(" (")
	builder.WriteString(caller)
	builder.WriteString(")")

	// Add fields
	for _, field := range fields {
		if field.Key != "timestamp" && field.Key != "level" && field.Key != "message" && field.Key != "caller" && field.Key != "module" {
			builder.WriteString(" ")
			builder.WriteString(field.Key)
			builder.WriteString("=")

			// Format the value based on its type
			switch v := field.Value.(type) {
			case string:
				builder.WriteString(v)
			case error:
				builder.WriteString(v.Error())
			default:
				builder.WriteString(fmt.Sprintf("%v", v))
			}
		}
	}

	builder.WriteString("\n")

	_, err := l.writer.Write([]byte(builder.String()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing log: %v\n", err)
	}
}

// WithCustomLogger sets a custom logger for the server
func WithCustomLogger(logger Logger) AppLayer {
	return func(s *Server) {
		s.Logger = logger
	}
}

// WithLogLevel sets the log level for the server
func WithLogLevel(level LogLevel) AppLayer {
	return func(s *Server) {
		s.Logger.SetLevel(level)
	}
}

// WithLogFormat sets the log format for the server
func WithLogFormat(format LogFormat) AppLayer {
	return func(s *Server) {
		s.Logger.SetFormat(format)
	}
}

// WithModuleLogLevel sets the log level for a specific module
func WithModuleLogLevel(module string, level LogLevel) AppLayer {
	return func(s *Server) {
		SetModuleLevel(module, level)
	}
}

// WithLogRegistry sets a custom log registry for the server
func WithLogRegistry(registry *LogRegistry) AppLayer {
	return func(s *Server) {
		if logger, ok := s.Logger.(*StructuredLogger); ok {
			logger.SetRegistry(registry)
		}
	}
}
