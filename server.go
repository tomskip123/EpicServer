package server

import (
	"log"
	"net/http"
	"os"

	"github.com/cyberthy/server/handlers"
	"github.com/cyberthy/server/helpers"
	"github.com/cyberthy/server/middleware"
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
	_ "github.com/joho/godotenv/autoload"
)

var Routes []*structs.HandlerDef

func AddRoute(handler *structs.HandlerDef) {
	Routes = append(Routes, handler)
}

type Server struct {
	App      *structs.App
	Gin      *gin.Engine
	DbConfig *structs.DbConfig
}

func (s *Server) SetupServer() {
	if s.App == nil {
		panic("Please define app")
	}

	if s.App.ServerConfig == nil {
		panic("Please add server config")
	}

	r, app := helpers.InitApp(
		os.Getenv("GOOGLE_CLIENT_ID"),
		os.Getenv("GOOGLE_CLIENT_SECRET"),
		os.Getenv("OAUTH_CALLBACK"),
		s.App.ServerConfig,
		s.DbConfig,
	)

	s.App = app
	s.Gin = r
}

func (s *Server) AddHealthChecker() {
	// this is bypassing all the middleware that the app uses.
	healthCheckerGroup := s.Gin.Group("/")
	{
		healthCheckerGroup.GET("/health_check_", func(ctx *gin.Context) {
			ctx.Status(http.StatusOK)
		})
	}
}

func (s *Server) RegisterBaseMiddleware() {
	middleware.RegisterBaseMiddleware(s.Gin, s.App)
}

func (s *Server) RegisterAuthMiddleware() {
	s.Gin.Use(middleware.AuthMiddleware(s.App))
}

func (s *Server) RegisterAnalyticsMiddleware() {
	s.Gin.Use(middleware.AnalyticsMiddleware())
}

func (s *Server) RegisterAuthRoutes() {
	handlers.RegisterAuthRoutes(s.Gin, s.App)
}

func (s *Server) RegisterNotifcationRoutes() {
	handlers.RegisterNotificationsRoutes(s.Gin, s.App)
}

func (s *Server) RegisterRoutes() {
	for _, handler := range Routes {

		handlerAndMiddleware := helpers.MiddlewareInject(handler.Middleware, s.App)
		handlerAndMiddleware = append(handlerAndMiddleware, handler.Handler(s.App))

		// Register handlers
		if handler.Handler != nil {
			switch handler.Method {
			case http.MethodGet:
				s.Gin.GET(handler.Path, handlerAndMiddleware...)
			case http.MethodPost:
				s.Gin.POST(handler.Path, handlerAndMiddleware...)
			case http.MethodPut:
				s.Gin.PUT(handler.Path, handlerAndMiddleware...)
			case http.MethodDelete:
				s.Gin.DELETE(handler.Path, handlerAndMiddleware...)
			case http.MethodPatch:
				s.Gin.PATCH(handler.Path, handlerAndMiddleware...)
			default:
				log.Fatalf("Method not supported")
			}
		}
	}

	// scheduler := tasks.RegisterTodoTasks(app)
	// defer scheduler.Stop()
}

func (s *Server) StartServer() {
	gin.SetMode(gin.ReleaseMode)
	helpers.StartServer(s.Gin, s.App)
}
