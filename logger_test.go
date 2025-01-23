package EpicServer

import (
	"bytes"
	"testing"
)

func TestDefaultLogger(t *testing.T) {
	logger := defaultLogger()
	if logger == nil {
		t.Error("defaultLogger() returned nil")
	}
}

func TestLogger_Levels(t *testing.T) {
	var buf bytes.Buffer
	logger := &testLogger{output: &buf}

	tests := []struct {
		name     string
		logFunc  func(string)
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

// testLogger implementation for testing
type testLogger struct {
	output *bytes.Buffer
}

func (l *testLogger) Info(msg string) {
	l.output.WriteString("[INFO] " + msg + "\n")
}

func (l *testLogger) Error(msg string) {
	l.output.WriteString("[ERROR] " + msg + "\n")
}

func (l *testLogger) Debug(msg string) {
	l.output.WriteString("[DEBUG] " + msg + "\n")
}
