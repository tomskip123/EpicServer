package structs

import (
	"github.com/gin-gonic/gin"
)

type ServerHandlerFunc = func(app *App) gin.HandlerFunc

type MiddlewareName = string

type HandlerDef struct {
	Name              string
	Method            string
	Path              string
	Middleware        []ServerHandlerFunc
	Handler           ServerHandlerFunc
	ExcludeMiddleware []MiddlewareName
}

type SchedulerHandlerFunc = func(app *App)

type SchedulerDef struct {
	Name    string
	Handler SchedulerHandlerFunc
}
