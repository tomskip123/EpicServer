package EpicServer

import (
	"fmt"

	"github.com/gin-gonic/gin"
	_ "github.com/joho/godotenv/autoload"
)

type Server struct {
	config      *Config
	engine      *gin.Engine
	logger      Logger
	db          DatabaseProvider
	hooks       Hooks
	publicPaths map[string]bool
}

type NewServerParam struct {
	Configs  []Option
	AppLayer []AppLayer
}

// build default server
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
		config: config,
		engine: gin.New(),
		logger: defaultLogger(),
	}

	// for us to then loop through the given options that would give access to gin
	// another server features

	for _, opt := range p1.AppLayer {
		opt(s)
	}

	return s
}

// method for starting the server
func (s *Server) Start() error {
	return s.engine.Run(fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port))
}

// DB is a method for accessing defined database providers!
func (s *Server) DB() DatabaseProvider {
	if s.db == nil {
		panic("no database provider defined")
	}

	return s.db
}

// setting up default config with sensible defaults
func defaultConfig() *Config {
	c := &Config{}

	c.Server.Host = "localhost"
	c.Server.Port = 3000

	return c
}

// Need an option to provide methods that make changes to the engine
// We expose access to the underlying app layer to make changes directory to the config

type AppLayer func(*Server)

// adds a very rudimentary health checker
// this should surfice for any checkers.
func WithHealthCheck(path string) AppLayer {
	return func(s *Server) {
		s.engine.GET(path, func(ctx *gin.Context) {
			ctx.Status(200)
		})
	}
}

// We have a very basic middleware that supports compression and force https when it can
func WithCompression() AppLayer {
	return func(s *Server) {
		s.engine.Use(CompressMiddleware)
	}
}

// WithRemoveWWW adds middleware to remove the www. prefix in a domain.
func WithRemoveWWW() AppLayer {
	return func(s *Server) {
		s.engine.Use(RemoveWWWMiddleware())
	}
}

// WithCors registers middleware that register cors settings!
// This should support more options like accept headers etc.
func WithCors(origins []string) AppLayer {
	return func(s *Server) {
		s.engine.Use(CorsMiddleware(origins))
	}
}

// WithEnvironment sets how to run gin
func WithEnironment(environment string) AppLayer {
	return func(s *Server) {
		gin.SetMode(gin.ReleaseMode)
	}

}

// With HTTP2 sets gin to allow http2
func WithHttp2() AppLayer {
	return func(s *Server) {
		s.engine.UseH2C = true
	}
}
