package epicserver

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

var statusRecorderPool = sync.Pool{
	New: func() any { return &statusRecorder{} },
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int
}

func acquireStatusRecorder(w http.ResponseWriter) *statusRecorder {
	rec := statusRecorderPool.Get().(*statusRecorder)
	rec.ResponseWriter = w
	rec.status = http.StatusOK
	rec.written = 0
	return rec
}

func releaseStatusRecorder(rec *statusRecorder) {
	rec.ResponseWriter = nil
	statusRecorderPool.Put(rec)
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.written += n
	return n, err
}

// RequestLogger logs requests according to the provided format.
// Supported formats: "off", "simple", "concise", "detailed", "auto".
// - simple:   method path status
// - concise:  method path status duration bytes
// - detailed: method path status duration bytes remoteAddr userAgent headers
// - auto:     detailed if isDebug is true, otherwise concise
func RequestLogger(l *Logger, isDebug bool, format string) Middleware {
	mode := strings.ToLower(strings.TrimSpace(format))
	if mode == "" {
		mode = "off"
	}
	if mode == "auto" {
		if isDebug {
			mode = "detailed"
		} else {
			mode = "concise"
		}
	}
	if mode == "detailed" && !isDebug {
		mode = "concise"
	}
	if mode == "off" {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			start := time.Now()
			rec := acquireStatusRecorder(w)
			next.ServeHTTP(rec, req)
			dur := time.Since(start)

			path := req.URL.Path
			if q := req.URL.RawQuery; q != "" {
				path += "?" + q
			}

			switch mode {
			case "simple":
				l.Info.Printf("%s %s %d", req.Method, path, rec.status)
			case "concise":
				l.Info.Printf("%s %s %d %s %d", req.Method, path, rec.status, dur, rec.written)
			case "detailed":
				l.Debug.Printf(
					"REQ %s %s status=%d dur=%s bytes=%d from=%s ua=%q headers=%v",
					req.Method, path, rec.status, dur, rec.written, req.RemoteAddr, req.UserAgent(), req.Header,
				)
			default:
				// Unknown format: default to concise
				l.Info.Printf("%s %s %d %s %d", req.Method, path, rec.status, dur, rec.written)
			}

			releaseStatusRecorder(rec)
		})
	}
}
