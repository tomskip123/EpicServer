package server

import (
	"log"
	"net/http"
	"os"

	"github.com/cyberthy/server/handlers"
	"github.com/cyberthy/server/helpers"
	"github.com/cyberthy/server/middleware"
	"github.com/cyberthy/server/static"
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
	_ "github.com/joho/godotenv/autoload"
)

var Routes []*structs.HandlerDef

func AddRoute(handler *structs.HandlerDef) {
	Routes = append(Routes, handler)
}

func StartServer(
	staticConfig *static.Config,
	serverConfig *structs.ServerConfig,
	dbConfig *structs.DbConfig,
	initFunc structs.InitFunc,
) {

	r, app := helpers.InitApp(
		os.Getenv("GOOGLE_CLIENT_ID"),
		os.Getenv("GOOGLE_CLIENT_SECRET"),
		os.Getenv("OAUTH_CALLBACK"),
		serverConfig,
		dbConfig,
		staticConfig,
	)

	// this is bypassing all the middleware that the app uses.
	healthCheckerGroup := r.Group("/")
	{
		healthCheckerGroup.GET("/health_check_", func(ctx *gin.Context) {
			ctx.Status(http.StatusOK)
		})
	}

	middleware.RegisterBaseMiddleware(r, app)
	static.RegisterStaticRoutes(r, staticConfig)
	handlers.RegisterAuthRoutes(r, app)
	handlers.RegisterNotificationsRoutes(r, app)

	gin.SetMode(gin.ReleaseMode)

	for _, handler := range Routes {

		handlerAndMiddleware := helpers.MiddlewareInject(handler.Middleware, app)
		handlerAndMiddleware = append(handlerAndMiddleware, handler.Handler(app))

		// Register handlers
		if handler.Handler != nil {
			switch handler.Method {
			case http.MethodGet:
				r.GET(handler.Path, handlerAndMiddleware...)
			case http.MethodPost:
				r.POST(handler.Path, handlerAndMiddleware...)
			case http.MethodPut:
				r.PUT(handler.Path, handlerAndMiddleware...)
			case http.MethodDelete:
				r.DELETE(handler.Path, handlerAndMiddleware...)
			case http.MethodPatch:
				r.PATCH(handler.Path, handlerAndMiddleware...)
			default:
				log.Fatalf("Method not supported")
			}
		}
	}

	// scheduler := tasks.RegisterTodoTasks(app)
	// defer scheduler.Stop()

	if initFunc != nil {
		initFunc(r, app)
	}

	// start
	helpers.StartServer(r, app)
}
