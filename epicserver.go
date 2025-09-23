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

	"github.com/go-chi/chi/v5"
	"github.com/tomskip123/EpicServer/config"
	"golang.org/x/oauth2"
)

type EZApp struct {
	Render  *Renderer
	Logger  *Logger
	IsDebug bool
	Config  *config.Config
	Errors  []error
}

// EpicServer builder struct
type EpicServerBuilder struct {
	App          *EZApp
	mux          chi.Router
	tls          *tls.Config
	Controllers  ControllerBuilder
	RouteBuilder *RouteBuilder
}

// return new instance of EpicServerBuilder
func New(configPath string, viewOption ...ViewOption) *EpicServerBuilder {
	// first we try loading from config files.
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Printf("warning: load config: %v", err)
	}

	// create logger instance
	logger := NewLogger(&cfg.Logger)

	// create builder
	b := &EpicServerBuilder{}
	// create app context
	b.App = &EZApp{Logger: logger, IsDebug: cfg.Logger.IsDebug, Config: &cfg}

	// create route builder
	rb := newRouteBuilder(chi.NewRouter(), b.App)
	if f := strings.ToLower(strings.TrimSpace(cfg.Logger.RequestLogFormat)); f != "" && f != "off" {
		rb.Use(RequestLogger(logger, cfg.Logger.IsDebug, f))
	}
	// create renderer - depends on route builder
	renderer := NewRenderer(rb.mux, rb.middleware, rb, logger, viewOption...)

	// wire up other dependencies
	b.RouteBuilder = rb
	b.mux = rb.mux
	b.App.Render = renderer

	// create controller builder - depends on route builder
	b.Controllers = newControllerBuilder(rb)

	b.App.Errors = make([]error, 0)
	b.tls = nil

	if err := loadDotEnv(); err != nil {
		wrapped := fmt.Errorf("load .env: %w", err)
		b.App.Logger.Error.Printf("%v", wrapped)
		b.App.Errors = append(b.App.Errors, wrapped)
	}

	return b
}

// Use appends global middleware applied to all routes/views created after this call.
func (b *EpicServerBuilder) Use(mw ...Middleware) *EpicServerBuilder {
	b.RouteBuilder.middleware = append(b.RouteBuilder.middleware, mw...)
	return b
}

func (b *EpicServerBuilder) Routes(fn func(r *RouteBuilder)) *EpicServerBuilder {
	fn(b.RouteBuilder)
	return b
}

// Auth wires up OAuth-backed authentication handlers with cookie sessions.
func (b *EpicServerBuilder) Auth(config *oauth2.Config, opts ...AuthOption) *AuthModule {
	if config == nil {
		b.App.Errors = append(b.App.Errors, errors.New("oauth2 config is required"))
		return nil
	}
	return newAuthModule(b.mux, b.RouteBuilder.middleware, config, opts...)
}

// start server with system cancel listening for cancel.
func (b *EpicServerBuilder) Start(app *EZApp) error {
	// log app name
	if b.App.Config.AppName != "" {
		b.App.Logger.Info.Printf("Starting %s", b.App.Config.AppName)
	}

	if len(b.App.Errors) > 0 {
		return errors.Join(b.App.Errors...)
	}

	// need to pass injectables
	b.Controllers.Build(app)

	// check if auth is enabled
	if b.App.Config.Features.EnableAuth {
		b.App.Logger.Info.Printf("Auth is enabled")

		// setup simple auth
		authModule, _ := configureAuth(b)
		if authModule == nil {
			b.App.Logger.Warn.Printf("Auth is enabled but not configured, please fix")
			return nil
		}

		// session middleware loader
		b.Use(authModule.SessionLoaderMiddleware())
	}

	b.App.Logger.Info.Printf("Starting server")

	if err := b.RouteBuilder.apply(); err != nil {
		b.App.Errors = append(b.App.Errors, err)
	}

	if len(b.App.Errors) > 0 {
		return errors.Join(b.App.Errors...)
	}

	host := "localhost"
	port := 8080
	if b.App.Config.Server.Host != "" {
		host = b.App.Config.Server.Host
	}
	if b.App.Config.Server.Port != 0 {
		port = b.App.Config.Server.Port
	}

	httpServer := &http.Server{
		Addr:    net.JoinHostPort(host, strconv.Itoa(port)),
		Handler: b.mux,
	}

	// setup cancel on system signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}()

	// start server
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

const (
	authEnvPrefix    = "BULLET_AUTH"
	authLoginPath    = "/auth/login"
	authCallbackPath = "/auth/callback"
	authLogoutPath   = "/auth/logout"
)

func configureAuth(srv *EpicServerBuilder) (*AuthModule, error) {
	if !authEnvConfigured(authEnvPrefix) {
		return nil, nil
	}

	config, err := AuthConfigFromEnv(authEnvPrefix)
	if err != nil {
		panic("auth config error: " + err.Error())
	}

	options := []AuthOption{
		WithLoginPath(authLoginPath),
		WithCallbackPath(authCallbackPath),
		WithLogoutPath(authLogoutPath),
		WithLoginRedirect("/"),
		WithLogoutRedirect("/"),
		WithFailureRedirect("/"),
	}

	// INSECURE: allow cookies over HTTP for local dev
	options = append(options, WithInsecureCookies())

	module := srv.Auth(config, options...)
	return module, nil
}

func authEnvConfigured(prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "_")
	prefix = strings.ToUpper(prefix)

	lookup := func(suffix string) bool {
		_, ok := os.LookupEnv(prefix + "_" + suffix)
		return ok
	}

	idOK := lookup("CLIENT_ID")
	secretOK := lookup("CLIENT_SECRET")
	if !idOK || !secretOK {
		return false
	}

	if lookup("PROVIDER") {
		return true
	}

	authURL := lookup("AUTH_URL")
	tokenURL := lookup("TOKEN_URL")
	return authURL && tokenURL
}
