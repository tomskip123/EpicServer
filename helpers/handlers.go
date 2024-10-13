package helpers

import (
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
)

func MiddlewareInject(middleware []structs.ServerHandlerFunc, app *structs.App) []gin.HandlerFunc {
	var handlers []gin.HandlerFunc
	for _, m := range middleware {
		handlers = append(handlers, m(app))
	}
	return handlers
}
