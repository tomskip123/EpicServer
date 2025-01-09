package EpicServer

import (
	"fmt"

	"github.com/gin-gonic/gin"
	_ "github.com/joho/godotenv/autoload"
)

type Server struct {
	Config      *Config
	Engine      *gin.Engine
	Logger      Logger
	Hooks       Hooks
	PublicPaths map[string]bool
	AuthConfigs map[string]*Auth
	Db          interface{}
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
		Config: config,
		Engine: gin.New(),
		Logger: defaultLogger(),
		Hooks:  defaultHooks(),
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
	return s.Engine.Run(fmt.Sprintf("%s:%d", s.Config.Server.Host, s.Config.Server.Port))
}

// setting up default config with sensible defaults
func defaultConfig() *Config {
	c := &Config{}

	c.Server.Host = "localhost"
	c.Server.Port = 3000

	return c
}

// set up default hooks
func defaultHooks() Hooks {
	h := Hooks{}

	h.Auth = &DefaultAuthHooks{}

	return h
}

// Need an option to provide methods that make changes to the engine
// We expose access to the underlying app layer to make changes directory to the config

type AppLayer func(*Server)

// adds a very rudimentary health checker
// this should surfice for any checkers.
func WithHealthCheck(path string) AppLayer {
	return func(s *Server) {
		s.Engine.GET(path, func(ctx *gin.Context) {
			ctx.Status(200)
		})
	}
}

// We have a very basic middleware that supports compression and force https when it can
func WithCompression() AppLayer {
	return func(s *Server) {
		s.Engine.Use(CompressMiddleware)
	}
}

// WithRemoveWWW adds middleware to remove the www. prefix in a domain.
func WithRemoveWWW() AppLayer {
	return func(s *Server) {
		s.Engine.Use(RemoveWWWMiddleware())
	}
}

// WithCors registers middleware that register cors settings!
// This should support more options like accept headers etc.
func WithCors(origins []string) AppLayer {
	return func(s *Server) {
		s.Engine.Use(CorsMiddleware(origins))
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
		s.Engine.UseH2C = true
	}
}
