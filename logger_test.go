package EpicServer

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

func TestDefaultLogger(t *testing.T) {
	logger := defaultLogger(os.Stdout)
	if logger == nil {
		t.Error("defaultLogger() returned nil")
	}
}

func TestLogger_Levels(t *testing.T) {
	var buf bytes.Buffer

	logger := defaultLogger(&buf)

	tests := []struct {
		name     string
		logFunc  func(args ...interface{})
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
			// buf.Reset()
			tt.logFunc(tt.message)

			output := buf.String()
			fmt.Println(output)

			if !bytes.Contains(buf.Bytes(), []byte(tt.wantText)) {
				t.Errorf("logger output = %q, want %q", buf.String(), tt.wantText)
			}
		})
	}
}
