package epicserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/oauth2"
)

// EpicServer builder struct
type EpicServerBuilder struct {
	mux          *http.ServeMux
	port         uint16
	tls          *tls.Config
	middleware   []Middleware
	logger       *log.Logger
	errs         []error
	Controllers  ControllerBuilder
	RouteBuilder *RouteBuilder
}

var (
	logger  *log.Logger
	IsDebug = false
)

// return new instance of EpicServerBuilder
func New() *EpicServerBuilder {
	logger = log.New(os.Stdout, "", log.LstdFlags)

	rb := newRouteBuilder(http.NewServeMux(), nil)

	b := &EpicServerBuilder{
		mux:          rb.mux,
		port:         8080,
		logger:       logger,
		errs:         make([]error, 0),
		Controllers:  newControllerBuilder(rb),
		RouteBuilder: rb,
	}

	if err := loadDotEnv(); err != nil {
		wrapped := fmt.Errorf("load .env: %w", err)
		b.logger.Printf("%v", wrapped)
		b.errs = append(b.errs, wrapped)
	}

	return b
}

// Use appends global middleware applied to all routes/views created after this call.
func (b *EpicServerBuilder) Use(mw ...Middleware) *EpicServerBuilder {
	b.middleware = append(b.middleware, mw...)
	return b
}

func (b *EpicServerBuilder) Routes(fn func(r *RouteBuilder)) *EpicServerBuilder {
	fn(b.RouteBuilder)

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

	b.Controllers.Build()

	if err := b.RouteBuilder.apply(); err != nil {
		b.errs = append(b.errs, err)
	}

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

func loadDotEnv(paths ...string) error {
	if len(paths) == 0 {
		paths = []string{".env"}
	}

	for _, path := range paths {
		err := parseDotEnvFile(path)
		if err == nil {
			continue
		}
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return fmt.Errorf("load env file %q: %w", path, err)
	}

	return nil
}

func parseDotEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		if strings.HasPrefix(text, "export ") {
			text = strings.TrimSpace(strings.TrimPrefix(text, "export"))
		}

		key, value, found := strings.Cut(text, "=")
		if !found {
			return fmt.Errorf("missing '=' at %s:%d", path, line)
		}

		key = strings.TrimSpace(key)
		if key == "" {
			return fmt.Errorf("empty key at %s:%d", path, line)
		}

		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			switch {
			case value[0] == '"' && value[len(value)-1] == '"':
				unquoted, err := strconv.Unquote(value)
				if err != nil {
					return fmt.Errorf("invalid quoted value at %s:%d: %w", path, line, err)
				}
				value = unquoted
			case value[0] == '\'' && value[len(value)-1] == '\'':
				value = value[1 : len(value)-1]
			default:
				if idx := strings.Index(value, " #"); idx >= 0 {
					value = strings.TrimSpace(value[:idx])
				}
			}
		} else if idx := strings.Index(value, " #"); idx >= 0 {
			value = strings.TrimSpace(value[:idx])
		}

		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set env %q: %w", key, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	return nil
}
