package epicserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// EpicServer builder struct
type EpicServerBuilder struct {
	mux        *http.ServeMux
	port       uint16
	tls        *tls.Config
	middleware []Middleware
	logger     *log.Logger
	errs       []error
}

// return new instance of EpicServerBuilder
func New() *EpicServerBuilder {
	return &EpicServerBuilder{
		mux:    http.NewServeMux(),
		port:   8080,
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

func (b *EpicServerBuilder) Routes(fn func(r *RouteBuilder)) *EpicServerBuilder {
	rb := newRouteBuilder(b.mux, b.middleware)
	fn(rb)
	if err := rb.apply(); err != nil {
		b.errs = append(b.errs, err)
	}
	return b
}

// start server with system cancel listening for cancel.
func (b *EpicServerBuilder) Start() error {
	if len(b.errs) > 0 {
		return errors.Join(b.errs...)
	}

	b.logger.Printf("Starting server")

	httpServer := &http.Server{
		Addr:    net.JoinHostPort("localhost", "8080"),
		Handler: b.mux,
	}

	// ctrl + c
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}()

	log.Printf("listening on %s\n", httpServer.Addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "error listening and serving: %s\n", err)
	}

	return nil
}
