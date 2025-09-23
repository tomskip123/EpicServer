package epicserver

import (
	"log"
	"os"

	"github.com/tomskip123/EpicServer/config"
)

type Logger struct {
	Info  *log.Logger
	Warn  *log.Logger
	Error *log.Logger
	Debug *log.Logger
}

func NewLogger(cfg *config.LoggerConfig) *Logger {
	flags := log.LstdFlags | log.Lmsgprefix

	if !cfg.IsDebug {
		flags &^= log.Lshortfile
	}

	return &Logger{
		Info:  log.New(os.Stdout, "INFO: ", flags),
		Warn:  log.New(os.Stdout, "WARN: ", flags),
		Error: log.New(os.Stderr, "ERROR: ", flags),
		Debug: log.New(os.Stdout, "DEBUG: ", flags),
	}
}
