// Package EpicServer provides a powerful, flexible, and production-ready web server built on top of Gin framework.
//
// Key features:
//   - Flexible configuration system
//   - Built-in authentication
//   - Database support (MongoDB, PostgreSQL, MySQL, GORM)
//   - Caching system
//   - Static file serving
//   - Middleware support
//   - SPA support
//
// Basic usage:
//
//	server := EpicServer.NewServer([]EpicServer.Option{
//	    EpicServer.SetSecretKey([]byte("your-secret-key")),
//	})
//
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServer.WithHealthCheck("/health"),
//	    EpicServer.WithEnvironment("development"),
//	})
//
//	server.Start()
package EpicServer

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/joho/godotenv/autoload"
)

// Server represents the main server instance containing all necessary dependencies
type Server struct {
	Config      *Config
	Engine      *gin.Engine
	Logger      Logger
	Hooks       Hooks
	PublicPaths map[string]bool
	AuthConfigs map[string]*Auth
	Db          map[string]interface{}
	Cache       map[string]interface{}
	srv         *http.Server
	cancel      context.CancelFunc
	errors      []error    // Store initialization errors
	mu          sync.Mutex // Mutex to protect access to srv
}

// ServerOption represents a configuration option for the server
type ServerOption func(*Server) error

// NewServer creates and initializes a new server instance with the provided configuration
// It applies all configurations and app layers in the order they are provided
// Panics if no secret key is set
func NewServer(options []Option) *Server {
	// Initialize the server with default configuration
	config := defaultConfig()

	// Apply options to modify the configuration
	for _, opt := range options {
		opt(config)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		// Instead of panicking, return a server with the error
		s := &Server{
			Config: config,
			errors: []error{err},
		}
		return s
	}

	// Initialize Gin engine
	engine := gin.New()

	s := &Server{
		Config:      config,
		Engine:      engine,
		PublicPaths: make(map[string]bool),
		AuthConfigs: make(map[string]*Auth),
		Db:          make(map[string]interface{}),
		Cache:       make(map[string]interface{}),
		errors:      make([]error, 0),
	}

	// Initialize the logger
	s.Logger = defaultLogger(os.Stdout)

	// Setup default hooks
	s.Hooks = defaultHooks(s)

	// Setup default AppLayers
	defaultLayers := []AppLayer{
		WithLoggerMiddleware(), // Add the logger to the context first
		WithHealthCheck("/health"),
		WithCompression(),
		WithRemoveWWW(),
		WithEnvironment(config.Server.Environment),
	}

	// Apply app layers
	for _, layer := range defaultLayers {
		layer(s)
	}

	return s
}

// HasErrors returns true if the server has initialization errors
func (s *Server) HasErrors() bool {
	return len(s.errors) > 0
}

// GetErrors returns all initialization errors
func (s *Server) GetErrors() []error {
	return s.errors
}

// AddError adds an error to the server's error list
func (s *Server) AddError(err error) {
	s.errors = append(s.errors, err)
}

// UpdateAppLayer allows adding new application layers to an existing server instance
func (s *Server) UpdateAppLayer(layers []AppLayer) {
	if s.HasErrors() {
		s.Logger.Error("Server has initialization errors, skipping app layer updates",
			F("error_count", len(s.errors)))
		return
	}

	for _, layer := range layers {
		layer(s)
	}
}

// Start initiates the server on the configured host and port
func (s *Server) Start() error {
	// Check for initialization errors
	if s.HasErrors() {
		errMsgs := "Server initialization errors: "
		for i, err := range s.errors {
			if i > 0 {
				errMsgs += ", "
			}
			errMsgs += err.Error()
		}
		return fmt.Errorf(errMsgs)
	}

	// Create a new context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	addr := fmt.Sprintf("%s:%d", s.Config.Server.Host, s.Config.Server.Port)
	s.Logger.Info("Starting server",
		F("address", addr),
		F("environment", s.Config.Server.Environment))

	s.mu.Lock()
	s.srv = &http.Server{
		Addr:    addr,
		Handler: s.Engine,
	}
	s.mu.Unlock()

	go func() {
		// Wait for the context to be canceled
		<-ctx.Done()
		s.Logger.Info("Server shutdown initiated")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		s.mu.Lock()
		srv := s.srv
		s.mu.Unlock()

		if srv != nil {
			if err := srv.Shutdown(shutdownCtx); err != nil {
				s.Logger.Error("Server shutdown error", F("error", err.Error()))
			}
		}
	}()

	// Start the server and return any errors
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	return srv.ListenAndServe()
}

// Stop gracefully stops the server
func (s *Server) Stop() error {
	s.mu.Lock()
	hasSrv := s.srv != nil
	s.mu.Unlock()

	if s.cancel != nil {
		s.cancel() // Call the cancel function to stop the server
		s.Logger.Info("Server stopping")
	}

	// If server was never started or already stopped
	if !hasSrv {
		return nil
	}

	// Wait a moment for the shutdown to complete
	time.Sleep(100 * time.Millisecond)
	return nil
}

// setting up default config with sensible defaults
func defaultConfig() *Config {
	c := &Config{}

	c.Server.Host = "localhost"
	c.Server.Port = 3000
	c.Server.Environment = "development"

	// Set secure defaults for security
	c.Security.SecureCookie = true

	return c
}

// set up default hooks
func defaultHooks(s *Server) Hooks {
	h := Hooks{}

	h.Auth = &DefaultAuthHooks{
		s: s,
	}

	return h
}

// Need an option to provide methods that make changes to the engine
// We expose access to the underlying app layer to make changes directory to the config

// AppLayer defines a function type that can modify the server configuration
type AppLayer func(*Server)

// WithHealthCheck creates a basic health check endpoint at the specified path
// Returns 200 OK when the server is running
func WithHealthCheck(path string) AppLayer {
	return func(s *Server) {
		s.Engine.GET(path, func(ctx *gin.Context) {
			ctx.Status(200)
		})
	}
}

// WithCompression adds compression middleware to the server
func WithCompression() AppLayer {
	return func(s *Server) {
		s.Engine.Use(CompressMiddleware)

		// Add module-based logging
		compressionLogger := s.Logger.WithModule("middleware.compression")
		compressionLogger.Debug("Compression middleware enabled")
	}
}

// WithRemoveWWW adds middleware to remove the www. prefix from domain names
func WithRemoveWWW() AppLayer {
	return func(s *Server) {
		s.Engine.Use(RemoveWWWMiddleware())

		// Add module-based logging
		wwwLogger := s.Logger.WithModule("middleware.www")
		wwwLogger.Debug("Remove WWW middleware enabled")
	}
}

// WithCors configures CORS settings for the specified origins
func WithCors(origins []string) AppLayer {
	return func(s *Server) {
		s.Engine.Use(CorsMiddleware(origins))

		// Add module-based logging
		corsLogger := s.Logger.WithModule("middleware.cors")
		corsLogger.Debug("CORS middleware enabled", F("allowed_origins", origins))
	}
}

// WithEnvironment sets the Gin framework's running mode
// Accepts: "development", "production", or "test"
func WithEnvironment(environment string) AppLayer {
	return func(s *Server) {
		if environment == "development" {
			gin.SetMode(gin.DebugMode)
		} else if environment == "production" {
			gin.SetMode(gin.ReleaseMode)
		} else {
			gin.SetMode(gin.TestMode)
		}

		// Add module-based logging
		envLogger := s.Logger.WithModule("middleware.environment")
		envLogger.Info("Environment set", F("mode", environment))
	}
}

// WithTrustedProxies configures the trusted proxy addresses for the server
func WithTrustedProxies(proxies []string) AppLayer {
	return func(s *Server) {
		s.Engine.SetTrustedProxies(proxies)

		// Add module-based logging
		proxyLogger := s.Logger.WithModule("middleware.proxy")
		proxyLogger.Debug("Trusted proxies configured", F("proxies", proxies))
	}
}

// WithHttp2 enables HTTP/2 support for the server
func WithHttp2() AppLayer {
	return func(s *Server) {
		s.Engine.UseH2C = true

		// Add module-based logging
		http2Logger := s.Logger.WithModule("middleware.http2")
		http2Logger.Debug("HTTP/2 support enabled")
	}
}

// WithLoggerMiddleware adds the server's logger to the gin context
// This should be added early in the middleware chain to ensure all subsequent middleware can access the logger
func WithLoggerMiddleware() AppLayer {
	return func(s *Server) {
		s.Engine.Use(LoggerMiddleware(s.Logger))

		// Log that the middleware has been added
		loggerMwLogger := s.Logger.WithModule("middleware.logger")
		loggerMwLogger.Debug("Logger middleware enabled")
	}
}
