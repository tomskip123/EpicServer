// Package EpicServer provides a powerful, flexible, and production-ready web server built on top of Gin framework.
//
// EpicServer is designed to simplify the development of robust web applications by providing
// a comprehensive set of features, sensible defaults, and a clean API. It handles many of the
// common tasks required when building web services, allowing developers to focus on business logic.
//
// # Key Features
//
//   - Flexible configuration system with environment variable support
//   - Built-in authentication with OAuth2/OIDC support (Google, GitHub, etc.)
//   - Database integrations (MongoDB, PostgreSQL, MySQL, GORM)
//   - Caching system for improved performance
//   - Static file serving and SPA support
//   - Extensive middleware options (logging, CORS, compression, etc.)
//   - Graceful shutdown handling
//
// # Basic Usage
//
//	package main
//
//	import (
//	    "github.com/tomskip123/EpicServer/v2"
//	)
//
//	func main() {
//	    // Create a new server with basic configuration
//	    server := EpicServer.NewServer([]EpicServer.Option{
//	        EpicServer.SetSecretKey([]byte("your-secret-key")),
//	        EpicServer.SetPort(8080),
//	    })
//
//	    // Apply application layers for additional functionality
//	    server.UpdateAppLayer([]EpicServer.AppLayer{
//	        EpicServer.WithHealthCheck("/health"),
//	        EpicServer.WithEnvironment("development"),
//	        EpicServer.WithLoggerMiddleware(),
//	    })
//
//	    // Add routes
//	    apiGroup := server.Engine.Group("/api")
//	    apiGroup.GET("/hello", func(c *gin.Context) {
//	        c.JSON(200, gin.H{"message": "Hello World"})
//	    })
//
//	    // Start the server (blocking call)
//	    if err := server.Start(); err != nil {
//	        panic(err)
//	    }
//	}
//
// # Authentication Example
//
//	// Configure OAuth providers
//	providers := []EpicServer.Provider{
//	    {
//	        Name:         "google",
//	        ClientId:     os.Getenv("GOOGLE_CLIENT_ID"),
//	        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
//	        Callback:     "http://localhost:8080/auth/callback/google",
//	    },
//	}
//
//	// Apply authentication middleware
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServer.WithAuth(providers, &EpicServer.SessionConfig{
//	        CookieName:      "auth_session",
//	        CookieSecure:    true,
//	        SessionDuration: 24 * time.Hour,
//	    }),
//	    EpicServer.WithAuthMiddleware(EpicServer.SessionConfig{
//	        CookieName: "auth_session",
//	    }),
//	})
//
// For more extensive documentation and examples, see the documentation site
// or the repository README.
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

// Server represents the main server instance containing all necessary dependencies and configuration.
// It serves as the central object for your application, providing access to all EpicServer features.
//
// The Server struct contains several exported fields that can be accessed directly:
//   - Config: Access to all configuration settings
//   - Engine: The underlying Gin engine for adding routes and middleware
//   - Logger: Structured logger for application logging
//   - Hooks: Extension points for custom behavior
//   - PublicPaths: Paths that don't require authentication
//   - AuthConfigs: Authentication providers configuration
//   - Db: Map of database connections (use type assertions to access specific implementations)
//   - Cache: Map of cache instances (use type assertions to access specific implementations)
//
// Example accessing the Gin engine to add routes:
//
//	apiGroup := server.Engine.Group("/api/v1")
//	apiGroup.GET("/users", GetUsersHandler)
//	apiGroup.POST("/users", CreateUserHandler)
//
// Example accessing a database connection:
//
//	if db, ok := server.Db["mongo"].(*mongo.Database); ok {
//	    collection := db.Collection("users")
//	    // Use the collection...
//	}
//
// Example accessing a cache instance:
//
//	if cache, ok := server.Cache["default"].(*MemoryCache); ok {
//	    value, found := cache.Get("user:123")
//	    // Use the cached value...
//	}
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

// NewServer creates and initializes a new server instance with the provided configuration options.
// It applies all configurations and default app layers in the order they are provided.
//
// The function expects a slice of Option functions that modify the server configuration.
// At minimum, you should provide a secret key for security-related features.
//
// If any configuration validation fails, the server will be created with initialization errors
// that can be checked with HasErrors() and GetErrors().
//
// Example:
//
//	server := EpicServer.NewServer([]EpicServer.Option{
//	    EpicServer.SetSecretKey([]byte("your-secret-key")),
//	    EpicServer.SetPort(8080),
//	    EpicServer.SetHost("0.0.0.0"),
//	    EpicServer.SetLogLevel("info"),
//	})
//
//	if server.HasErrors() {
//	    // Handle initialization errors
//	    fmt.Println("Server errors:", server.GetErrors())
//	    return
//	}
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
// Use this method to check if the server was properly initialized before starting it.
//
// Example:
//
//	if server.HasErrors() {
//	    log.Fatalf("Server initialization failed: %v", server.GetErrors())
//	}
func (s *Server) HasErrors() bool {
	return len(s.errors) > 0
}

// GetErrors returns all initialization errors
// Use this to get detailed information about what went wrong during server initialization.
func (s *Server) GetErrors() []error {
	return s.errors
}

// AddError adds an error to the server's error list
// This is primarily used internally, but can also be used by application code
// to track errors that should prevent the server from starting.
func (s *Server) AddError(err error) {
	s.errors = append(s.errors, err)
}

// UpdateAppLayer applies additional application layers to an existing server instance.
// App layers can add middleware, routes, authentication, database connections, and other features.
//
// If the server has initialization errors, the layers will not be applied.
//
// Example:
//
//	// Add authentication and database support
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServer.WithAuth(providers, sessionConfig),
//	    EpicServer.WithMongoDB("mongodb://localhost:27017", "mydatabase", "main"),
//	    EpicServer.WithLoggerMiddleware(),
//	})
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

// Start initiates the HTTP server on the configured host and port.
// This is a blocking call that will run until the server is stopped or an error occurs.
//
// The method checks for initialization errors before starting. If any errors are found,
// it will return an error without starting the server.
//
// The server supports graceful shutdown when Stop() is called or when the process
// receives an interrupt signal.
//
// Example:
//
//	if err := server.Start(); err != nil {
//	    log.Fatalf("Server failed to start: %v", err)
//	}
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

// Stop gracefully shuts down the server, allowing pending requests to complete.
// The server will wait up to 5 seconds for active connections to finish before
// forcefully closing them.
//
// This method is automatically called when the process receives an interrupt signal,
// but can also be called manually when needed.
//
// Example:
//
//	// Start the server in a goroutine
//	go func() {
//	    if err := server.Start(); err != http.ErrServerClosed {
//	        log.Printf("Server error: %v", err)
//	    }
//	}()
//
//	// Wait for some condition
//	time.Sleep(10 * time.Second)
//
//	// Gracefully shut down the server
//	if err := server.Stop(); err != nil {
//	    log.Printf("Shutdown error: %v", err)
//	}
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

// AppLayer defines a function type that can modify the server configuration.
// App layers are the primary way to add functionality to an EpicServer instance.
// They are applied through the NewServer function or later via UpdateAppLayer.
//
// Common app layers include:
//   - WithHealthCheck: Adds a health check endpoint
//   - WithEnvironment: Sets the server environment
//   - WithAuth: Adds authentication support
//   - WithMongoDB/WithPostgreSQL/WithMySQL: Adds database connections
//   - WithMemoryCache: Adds caching support
//   - WithStaticFiles: Serves static files
//   - WithSPA: Serves a Single Page Application
//
// Example usage:
//
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServer.WithHealthCheck("/health"),
//	    EpicServer.WithEnvironment("production"),
//	})
type AppLayer func(*Server)

// WithHealthCheck creates a basic health check endpoint at the specified path.
// The endpoint returns a 200 OK status code with an empty response when the server is running.
//
// This is useful for load balancers, container orchestration systems, and monitoring tools
// that need to verify the server is operational.
//
// Example:
//
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServer.WithHealthCheck("/health"),
//	})
//
// Then you can check server health with: curl http://localhost:3000/health
func WithHealthCheck(path string) AppLayer {
	return func(s *Server) {
		s.Engine.GET(path, func(ctx *gin.Context) {
			ctx.Status(200)
		})
	}
}

// WithCompression adds gzip compression middleware to the server.
// This reduces response size for compressible content types,
// improving transfer times and bandwidth usage.
//
// The middleware automatically detects if the client supports compression
// and only applies it to appropriate content types.
//
// Example:
//
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServer.WithCompression(),
//	})
func WithCompression() AppLayer {
	return func(s *Server) {
		s.Engine.Use(CompressMiddleware)

		// Add module-based logging
		compressionLogger := s.Logger.WithModule("middleware.compression")
		compressionLogger.Debug("Compression middleware enabled")
	}
}

// WithRemoveWWW adds middleware to redirect requests from www.domain.com to domain.com.
// This is a common practice for maintaining a consistent domain across all requests
// and avoiding duplicate content issues for SEO.
//
// Example:
//
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServer.WithRemoveWWW(),
//	})
func WithRemoveWWW() AppLayer {
	return func(s *Server) {
		s.Engine.Use(RemoveWWWMiddleware())

		// Add module-based logging
		wwwLogger := s.Logger.WithModule("middleware.www")
		wwwLogger.Debug("Remove WWW middleware enabled")
	}
}

// WithCors configures Cross-Origin Resource Sharing (CORS) settings for the specified origins.
// This allows browsers to make requests to your API from different domains.
//
// Parameters:
//   - origins: A slice of allowed origin domains or patterns (e.g., ["https://example.com", "https://*.example.org"])
//
// Example:
//
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServer.WithCors([]string{
//	        "https://myapp.com",
//	        "https://admin.myapp.com",
//	        "http://localhost:3000",
//	    }),
//	})
func WithCors(origins []string) AppLayer {
	return func(s *Server) {
		s.Engine.Use(CorsMiddleware(origins))

		// Add module-based logging
		corsLogger := s.Logger.WithModule("middleware.cors")
		corsLogger.Debug("CORS middleware enabled", F("allowed_origins", origins))
	}
}

// WithEnvironment sets the Gin framework's running mode based on the environment.
// This affects logging verbosity, error handling, and other behaviors.
//
// Parameters:
//   - environment: One of "development", "production", or "test"
//
// In development mode, detailed error messages and stack traces are shown.
// In production mode, error details are hidden from responses for security.
// Test mode is optimized for running automated tests.
//
// Example:
//
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServer.WithEnvironment("production"),
//	})
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

// WithTrustedProxies configures the trusted proxy addresses for the server.
// This is important when your server is behind load balancers, reverse proxies,
// or CDNs, as it allows proper handling of X-Forwarded-* headers.
//
// Parameters:
//   - proxies: A slice of IP addresses or CIDR ranges that are trusted
//
// Example:
//
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServer.WithTrustedProxies([]string{
//	        "127.0.0.1",
//	        "10.0.0.0/8",
//	        "172.16.0.0/12",
//	        "192.168.0.0/16",
//	    }),
//	})
func WithTrustedProxies(proxies []string) AppLayer {
	return func(s *Server) {
		s.Engine.SetTrustedProxies(proxies)

		// Add module-based logging
		proxyLogger := s.Logger.WithModule("middleware.proxy")
		proxyLogger.Debug("Trusted proxies configured", F("proxies", proxies))
	}
}

// WithHttp2 enables HTTP/2 support for the server using h2c (HTTP/2 cleartext).
// HTTP/2 provides benefits like multiplexing, header compression, and
// server push capabilities.
//
// Note that h2c is HTTP/2 without TLS encryption. For production use,
// HTTP/2 with TLS is recommended for better security and compatibility.
//
// Example:
//
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServer.WithHttp2(),
//	})
func WithHttp2() AppLayer {
	return func(s *Server) {
		s.Engine.UseH2C = true

		// Add module-based logging
		http2Logger := s.Logger.WithModule("middleware.http2")
		http2Logger.Debug("HTTP/2 support enabled")
	}
}

// WithLoggerMiddleware adds the structured logger to the Gin context,
// making it available to all request handlers. It also logs request information
// like method, path, status code, and timing.
//
// This middleware should be added early in the chain to ensure all subsequent
// middleware and handlers can access the logger.
//
// Example:
//
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServer.WithLoggerMiddleware(),
//	})
//
// Then in your handlers:
//
//	func MyHandler(c *gin.Context) {
//	    logger := EpicServer.GetLogger(c)
//	    logger.Info("Processing request", EpicServer.F("user_id", userID))
//	}
func WithLoggerMiddleware() AppLayer {
	return func(s *Server) {
		s.Engine.Use(LoggerMiddleware(s.Logger))

		// Log that the middleware has been added
		loggerMwLogger := s.Logger.WithModule("middleware.logger")
		loggerMwLogger.Debug("Logger middleware enabled")
	}
}
