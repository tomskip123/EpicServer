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
	"github.com/tomskip123/EpicServer/auth"
	"github.com/tomskip123/EpicServer/config"
	"golang.org/x/oauth2"
)

type EZAppWith[T any] struct {
	Auth     *auth.AuthModule
	Render   *Renderer
	Database *EpicServerDatabaseWith[T]
	User     *UserManagementWith[T]
	Logger   *Logger
	IsDebug  bool
	Config   *config.ConfigWith[T]
	Errors   []error
}

type EZApp = EZAppWith[struct{}]

// EpicServerBuilderWith wires all dependencies together for the given config type.
type EpicServerBuilderWith[T any] struct {
	App          *EZAppWith[T]
	mux          chi.Router
	tls          *tls.Config
	Controllers  ControllerBuilderWith[T]
	RouteBuilder *RouteBuilderWith[T]
}

type EpicServerBuilder = EpicServerBuilderWith[struct{}]

// New keeps the original behaviour without custom config fields.
func New(configPath string, viewOption ...ViewOption) *EpicServerBuilder {
	return NewWithConfig(configPath, struct{}{}, viewOption...)
}

// NewWithConfig loads configuration into the provided custom struct and wires
// the server with the typed config flowing through route builders, controllers,
// and middleware.
func NewWithConfig[T any](configPath string, customDefaults T, viewOption ...ViewOption) *EpicServerBuilderWith[T] {
	cfg, err := config.LoadWith(configPath, customDefaults)
	if err != nil {
		log.Printf("warning: load config: %v", err)
	}

	logger := NewLogger(&cfg.Logger)

	builder := &EpicServerBuilderWith[T]{}
	builder.App = &EZAppWith[T]{
		Logger:  logger,
		IsDebug: cfg.Logger.IsDebug,
		Config:  &cfg,
	}

	rb := newRouteBuilder[T](chi.NewRouter(), builder.App)
	if f := strings.ToLower(strings.TrimSpace(cfg.Logger.RequestLogFormat)); f != "" && f != "off" {
		rb.Use(RequestLogger(logger, cfg.Logger.IsDebug, f))
	}

	renderer := NewRenderer[T](rb.mux, rb.middleware, rb, logger, viewOption...)

	builder.RouteBuilder = rb
	builder.mux = rb.mux
	builder.App.Render = renderer
	builder.Controllers = newControllerBuilder[T](rb)
	builder.App.Errors = make([]error, 0)
	builder.tls = nil

	if err := loadDotEnv(); err != nil {
		wrapped := fmt.Errorf("load .env: %w", err)
		builder.App.Logger.Error.Printf("%v", wrapped)
		builder.App.Errors = append(builder.App.Errors, wrapped)
	}

	if cfg.Features.EnableDB {
		db := EpicServerDatabaseWith[T]{Config: builder.App.Config}
		epicServerDatabase, dbErr := db.Connect()
		if dbErr != nil {
			builder.App.Errors = append(builder.App.Errors, dbErr)
		} else {
			builder.App.Database = epicServerDatabase
		}
	}

	if cfg.Features.EnableUserMng {
		if !cfg.Features.EnableDB {
			builder.App.Errors = append(builder.App.Errors, errors.New("please enable database support"))
		}

		if !cfg.Features.EnableAuth {
			builder.App.Errors = append(builder.App.Errors, errors.New("please enable and configure auth support"))
		}

		builder.App.User = NewUserManagement[T](builder.App.Database, logger)
	}

	return builder
}

// Use appends global middleware applied to all routes/views created after this call.
func (b *EpicServerBuilderWith[T]) Use(mw ...Middleware) *EpicServerBuilderWith[T] {
	b.RouteBuilder.Use(mw...)
	return b
}

func (b *EpicServerBuilderWith[T]) Routes(fn func(r *RouteBuilderWith[T])) *EpicServerBuilderWith[T] {
	fn(b.RouteBuilder)
	return b
}

// Auth wires up OAuth-backed authentication handlers with cookie sessions.
func (b *EpicServerBuilderWith[T]) Auth(config *oauth2.Config, app *EZAppWith[T], opts ...auth.AuthOption) *auth.AuthModule {
	if config == nil {
		b.App.Errors = append(b.App.Errors, errors.New("oauth2 config is required"))
		return nil
	}
	var deps auth.Dependencies
	if app != nil {
		if app.Logger != nil {
			deps.Loggers = auth.Loggers{
				Error: app.Logger.Error,
				Info:  app.Logger.Info,
			}
		}
		deps.User = app.User
		if app.Config != nil {
			deps.DefaultProvider = app.Config.Auth.DefaultProvider
		}
	}
	return auth.New(b.mux, b.RouteBuilder.middleware, config, deps, opts...)
}

// Start boots the HTTP server after ensuring the configuration and dependencies are valid.
func (b *EpicServerBuilderWith[T]) Start(app *EZAppWith[T]) error {
	if b.App.Config.AppName != "" {
		b.App.Logger.Info.Printf("Starting %s", b.App.Config.AppName)
	}

	if len(b.App.Errors) > 0 {
		return errors.Join(b.App.Errors...)
	}

	// need to pass injectables
	b.Controllers.Build(app)

	if b.App.Config.Features.EnableAuth {
		b.App.Logger.Info.Printf("Auth is enabled")

		authModule, _ := configureAuth[T](b)
		if authModule == nil {
			b.App.Logger.Warn.Printf("Auth is enabled but not configured, please fix")
			return nil
		}

		b.Use(authModule.SessionLoaderMiddleware())
		b.App.Auth = authModule
	}

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
	httpServer.ErrorLog = log.New(b.App.Logger.Error.Writer(), "", 0)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		ctx, cancel := context.WithTimeout(context.Background(), b.App.Config.Server.ShutdownTimeout)
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

const (
	authEnvPrefix    = "BULLET_AUTH"
	authLoginPath    = "/auth/login"
	authCallbackPath = "/auth/callback"
	authLogoutPath   = "/auth/logout"
)

func configureAuth[T any](srv *EpicServerBuilderWith[T]) (*auth.AuthModule, error) {
	if cfg, err := oauthConfigFromAppConfig[T](srv.App.Config); err != nil {
		srv.App.Logger.Error.Printf("auth config error: %v", err)
	} else if cfg != nil {
		options := []auth.AuthOption{
			auth.WithLoginPath(authLoginPath),
			auth.WithCallbackPath(authCallbackPath),
			auth.WithLogoutPath(authLogoutPath),
			auth.WithLoginRedirect("/"),
			auth.WithLogoutRedirect("/"),
			auth.WithFailureRedirect("/"),
		}
		options = append(options, auth.WithInsecureCookies())
		module := srv.Auth(cfg, srv.App, options...)
		return module, nil
	}

	if !authEnvConfigured(authEnvPrefix) {
		return nil, nil
	}

	cfg, err := auth.AuthConfigFromEnv(authEnvPrefix)
	if err != nil {
		panic("auth config error: " + err.Error())
	}

	options := []auth.AuthOption{
		auth.WithLoginPath(authLoginPath),
		auth.WithCallbackPath(authCallbackPath),
		auth.WithLogoutPath(authLogoutPath),
		auth.WithLoginRedirect("/"),
		auth.WithLogoutRedirect("/"),
		auth.WithFailureRedirect("/"),
	}
	options = append(options, auth.WithInsecureCookies())
	module := srv.Auth(cfg, srv.App, options...)
	return module, nil
}

// oauthConfigFromAppConfig constructs an oauth2.Config from app Config if possible.
func oauthConfigFromAppConfig[T any](c *config.ConfigWith[T]) (*oauth2.Config, error) {
	if c == nil {
		return nil, nil
	}
	if len(c.Auth.OAuth2Providers) == 0 {
		return nil, nil
	}

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

	var endpoint oauth2.Endpoint
	providerName := strings.TrimSpace(p.Provider)
	if strings.TrimSpace(p.AuthURL) != "" || strings.TrimSpace(p.TokenURL) != "" {
		if strings.TrimSpace(p.AuthURL) == "" || strings.TrimSpace(p.TokenURL) == "" {
			return nil, fmt.Errorf("auth provider requires both authUrl and tokenUrl when set explicitly")
		}
		endpoint = oauth2.Endpoint{AuthURL: p.AuthURL, TokenURL: p.TokenURL}
	} else if providerName != "" {
		ep, exists := auth.EndpointForProvider(providerName)
		if !exists {
			return nil, fmt.Errorf("unknown auth provider %q", p.Provider)
		}
		endpoint = ep
	} else {
		return nil, fmt.Errorf("auth provider missing provider name or explicit URLs")
	}

	scopes := append([]string(nil), p.Scopes...)
	if len(scopes) == 0 && providerName != "" {
		if defaults := auth.DefaultScopesForProvider(providerName); len(defaults) > 0 {
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
