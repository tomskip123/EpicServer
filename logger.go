package epicserver

import (
	"log"
	"os"
)

type Logger struct {
	Info  *log.Logger
	Warn  *log.Logger
	Error *log.Logger
	Debug *log.Logger
}

func NewLogger(isDebug bool) *Logger {
	flags := log.LstdFlags | log.Lshortfile | log.Lmsgprefix

	if !isDebug {
		flags &^= log.Lshortfile
	}

	return &Logger{
		Info:  log.New(os.Stdout, "INFO: ", flags),
		Warn:  log.New(os.Stdout, "WARN: ", flags),
		Error: log.New(os.Stderr, "ERROR: ", flags),
		Debug: log.New(os.Stdout, "DEBUG: ", flags),
	}
}
