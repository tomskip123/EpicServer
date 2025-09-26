package epicserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"expvar"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/go-chi/chi/v5"
	"github.com/tomskip123/EpicServer/config"
	"golang.org/x/oauth2"
)

type EZApp struct {
	Render   *Renderer
	Database *EpicServerDatabase
	Logger   *Logger
	IsDebug  bool
	Config   *config.Config
	Errors   []error
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

	if cfg.Features.EnableDB {
		db := EpicServerDatabase{Config: b.App.Config}

		epicServerDatabase, dbError := db.Connect()
		if dbError != nil {
			b.App.Errors = append(b.App.Errors, dbError)
		}

		b.App.Database = epicServerDatabase
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

	// debug/metrics endpoints based on feature flags
	if b.App.Config.Features.EnablePprof {
		b.App.Logger.Info.Printf("pprof is enabled at /debug/pprof")
		b.mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
		b.mux.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
		b.mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
		b.mux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
		b.mux.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
	}
	if b.App.Config.Features.EnableMetrics {
		b.App.Logger.Info.Printf("expvar metrics enabled at /debug/vars")
		b.mux.Handle("/debug/vars", expvar.Handler())
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
		Addr:         net.JoinHostPort(host, strconv.Itoa(port)),
		Handler:      b.mux,
		ReadTimeout:  b.App.Config.Server.ReadTimeout,
		WriteTimeout: b.App.Config.Server.WriteTimeout,
	}
	// route server errors through our logger
	httpServer.ErrorLog = log.New(b.App.Logger.Error.Writer(), "", 0)

	// setup cancel on system signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		ctx, cancel := context.WithTimeout(context.Background(), b.App.Config.Server.ShutdownTimeout)
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
	// Prefer config-driven auth if present
	if cfg, err := oauthConfigFromAppConfig(srv.App.Config); err != nil {
		srv.App.Logger.Error.Printf("auth config error: %v", err)
	} else if cfg != nil {
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
		module := srv.Auth(cfg, options...)
		return module, nil
	}

	// Fallback to environment-based auth
	if !authEnvConfigured(authEnvPrefix) {
		return nil, nil
	}

	cfg, err := AuthConfigFromEnv(authEnvPrefix)
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
	module := srv.Auth(cfg, options...)
	return module, nil
}

// oauthConfigFromAppConfig constructs an oauth2.Config from app Config if possible.
func oauthConfigFromAppConfig(c *config.Config) (*oauth2.Config, error) {
	if c == nil {
		return nil, nil
	}
	if len(c.Auth.OAuth2Providers) == 0 {
		return nil, nil
	}

	// Pick the default provider if set, otherwise the first with credentials.
	var p config.OAuth2Provider
	var ok bool
	name := strings.ToLower(strings.TrimSpace(c.Auth.DefaultProvider))
	if name != "" {
		if prov, exists := c.Auth.OAuth2Providers[name]; exists {
			p = prov
			ok = true
		}
	}
	if !ok {
		for _, cand := range c.Auth.OAuth2Providers {
			if strings.TrimSpace(cand.ClientID) != "" && strings.TrimSpace(cand.ClientSecret) != "" {
				p = cand
				ok = true
				break
			}
		}
	}
	if !ok {
		return nil, nil
	}

	// Resolve endpoint
	var endpoint oauth2.Endpoint
	if strings.TrimSpace(p.AuthURL) != "" || strings.TrimSpace(p.TokenURL) != "" {
		if strings.TrimSpace(p.AuthURL) == "" || strings.TrimSpace(p.TokenURL) == "" {
			return nil, fmt.Errorf("auth provider requires both authUrl and tokenUrl when set explicitly")
		}
		endpoint = oauth2.Endpoint{AuthURL: p.AuthURL, TokenURL: p.TokenURL}
	} else if prov := strings.ToLower(strings.TrimSpace(p.Provider)); prov != "" {
		ep, exists := wellKnownProviderEndpoints[prov]
		if !exists {
			return nil, fmt.Errorf("unknown auth provider %q", p.Provider)
		}
		endpoint = ep
	} else {
		return nil, fmt.Errorf("auth provider missing provider name or explicit URLs")
	}

	// Resolve scopes
	scopes := append([]string(nil), p.Scopes...)
	if len(scopes) == 0 && strings.TrimSpace(p.Provider) != "" {
		if defaults, ok := wellKnownProviderScopes[strings.ToLower(p.Provider)]; ok {
			scopes = append(scopes, defaults...)
		}
	}

	cfg := &oauth2.Config{
		ClientID:     strings.TrimSpace(p.ClientID),
		ClientSecret: strings.TrimSpace(p.ClientSecret),
		Endpoint:     endpoint,
		Scopes:       scopes,
	}
	if ru := strings.TrimSpace(p.RedirectURL); ru != "" {
		cfg.RedirectURL = ru
	}
	return cfg, nil
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
