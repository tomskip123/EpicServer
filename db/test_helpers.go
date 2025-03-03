package EpicServerDb

import (
	"io"
	"testing"

	"github.com/tomskip123/EpicServer/v2"
)

// Helper to skip tests when running in short mode
func skipIfShort(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}
}

// Mock logger for testing
type testLogger struct{}

func (l *testLogger) Debug(msg string, fields ...EpicServer.LogField) {}
func (l *testLogger) Info(msg string, fields ...EpicServer.LogField)  {}
func (l *testLogger) Warn(msg string, fields ...EpicServer.LogField)  {}
func (l *testLogger) Error(msg string, fields ...EpicServer.LogField) {}
func (l *testLogger) Fatal(msg string, fields ...EpicServer.LogField) {}
func (l *testLogger) WithFields(fields ...EpicServer.LogField) EpicServer.Logger {
	return l
}
func (l *testLogger) WithModule(module string) EpicServer.Logger {
	return l
}
func (l *testLogger) SetOutput(w io.Writer)                        {}
func (l *testLogger) SetLevel(level EpicServer.LogLevel)           {}
func (l *testLogger) SetFormat(format EpicServer.LogFormat)        {}
func (l *testLogger) SetRegistry(registry *EpicServer.LogRegistry) {}
