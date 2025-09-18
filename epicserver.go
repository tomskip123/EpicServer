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

	"golang.org/x/oauth2"
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

// Use appends global middleware applied to all routes/views created after this call.
func (b *EpicServerBuilder) Use(mw ...Middleware) *EpicServerBuilder {
	b.middleware = append(b.middleware, mw...)
	return b
}

func (b *EpicServerBuilder) Routes(fn func(r *RouteBuilder)) *EpicServerBuilder {
	rb := newRouteBuilder(b.mux, b.middleware)
	fn(rb)
	if err := rb.apply(); err != nil {
		b.errs = append(b.errs, err)
	}
	return b
}

// View returns a new View bound to this builder's mux and middleware.
// Use this when you want to hold onto the View and mount handlers yourself.
func (b *EpicServerBuilder) View(opts ...ViewOption) *View {
	return NewView(b.mux, b.middleware, opts...)
}

// Views creates a View bound to this builder and passes it to fn for setup
// (e.g., mounting pages). Returns the builder for fluent chaining.
func (b *EpicServerBuilder) Views(fn func(*View), opts ...ViewOption) *EpicServerBuilder {
	v := NewView(b.mux, b.middleware, opts...)
	fn(v)
	return b
}

// Auth wires up OAuth-backed authentication handlers with cookie sessions.
func (b *EpicServerBuilder) Auth(config *oauth2.Config, opts ...AuthOption) *AuthModule {
	if config == nil {
		b.errs = append(b.errs, errors.New("oauth2 config is required"))
		return nil
	}
	return newAuthModule(b.mux, b.middleware, config, opts...)
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
