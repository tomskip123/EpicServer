package EpicServer

import (
	"context"
	"fmt"
	"net/http"
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
}

// NewServerParam defines the parameters needed to create a new server instance
type NewServerParam struct {
	Configs  []Option
	AppLayer []AppLayer
}

// NewServer creates and initializes a new server instance with the provided configuration
// It applies all configurations and app layers in the order they are provided
// Panics if no secret key is set
func NewServer(p1 *NewServerParam) *Server {
	// generate sensible default config

	config := defaultConfig()
	for _, opt := range p1.Configs {
		// loop through each option and apply whatever functionality has been defined
		opt(config)
	}

	if len(config.SecretKey) == 0 {
		panic("server secret key is required")
	}

	// We then define an initial setup for the server instance
	s := &Server{
		Config: config,
		Engine: gin.New(),
		Logger: defaultLogger(),
		Db:     make(map[string]interface{}),
		Cache:  make(map[string]interface{}),
	}

	s.Hooks = defaultHooks(s)

	// for us to then loop through the given options that would give access to gin
	// another server features

	for _, opt := range p1.AppLayer {
		opt(s)
	}

	return s
}

// UpdateAppLayer allows adding new application layers to an existing server instance
func (s *Server) UpdateAppLayer(p1 []AppLayer) {
	for _, opt := range p1 {
		opt(s)
	}
}

// Start initiates the server on the configured host and port
func (s *Server) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	s.srv = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.Config.Server.Host, s.Config.Server.Port),
		Handler: s.Engine,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.srv.Shutdown(shutdownCtx)
	}()

	return s.srv.ListenAndServe()
}

// Stop gracefully stops the server
func (s *Server) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

// setting up default config with sensible defaults
func defaultConfig() *Config {
	c := &Config{}

	c.Server.Host = "localhost"
	c.Server.Port = 3000

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
	}
}

// WithRemoveWWW adds middleware to remove the www. prefix from domain names
func WithRemoveWWW() AppLayer {
	return func(s *Server) {
		s.Engine.Use(RemoveWWWMiddleware())
	}
}

// WithCors configures CORS settings for the specified origins
func WithCors(origins []string) AppLayer {
	return func(s *Server) {
		s.Engine.Use(CorsMiddleware(origins))
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
	}
}

// WithTrustedProxies configures the trusted proxy addresses for the server
func WithTrustedProxies(proxies []string) AppLayer {
	return func(s *Server) {
		s.Engine.SetTrustedProxies(proxies)
	}
}

// WithHttp2 enables HTTP/2 support for the server
func WithHttp2() AppLayer {
	return func(s *Server) {
		s.Engine.UseH2C = true
	}
}
