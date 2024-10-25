package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
)

func CorsMiddleware(app *structs.App) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		origin := ctx.Request.Header.Get("Origin")

		if _, ok := ctx.Request.Header["Origin"]; ok {
			valid := false
			for _, v := range app.Config.Origins {
				if strings.HasPrefix(origin, v) {
					valid = true
					break
				}
			}
			if !valid {
				fmt.Println("Origin is not valid: " + origin)
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}
		}

		for _, allowedOrigin := range app.Config.Origins {
			if origin == allowedOrigin {
				ctx.Header("Access-Control-Allow-Origin", origin)
				break
			}
		}

		ctx.Header("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
		ctx.Header("Access-Control-Allow-Credentials", "true")
		ctx.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, Cache-Control, X-Requested-With, X-CSRF-Token, Accept-Encoding")
		if ctx.Request.Method == http.MethodOptions {
			ctx.AbortWithStatus(http.StatusOK)
			return
		}

		ctx.Next()
	}
}
