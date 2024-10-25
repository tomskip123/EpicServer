package middleware

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/cyberthy/server/helpers"
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
)

var excludeRoute = []string{
	"/",
	"/auth/google",
	"/auth/google/callback",
}

func AuthMiddleware(app *structs.App) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get the app struct from the context
		cookie, err := app.Auth.CookieHandler.ReadCookieHandler(ctx, "sesh_name")

		if err != nil {
			if helpers.RouteSkipsAuthMiddleware(
				app,
				ctx.Request.URL.Path,
				excludeRoute,
			) {
				ctx.Next()
				return
			}

			// Check if the Content-Type header is present
			if ctx.Request.Header.Get("Content-Type") == "application/json" {
				// ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}

			// Add a log here to capture context status
			ctx.Redirect(http.StatusSeeOther, "/")
			return
		}

		user := &structs.CookieContents{}
		err = json.Unmarshal([]byte(cookie), &user)
		if err != nil {
			log.Printf("Error unmarshalling cookie: %v", err)
		}

		// Add data to the request context
		ctx.Set("auth_user", user)
		ctx.Next()
	}
}

func WithAuth(app *structs.App, requiredFeatures []string, handler func(ctx *gin.Context, user *structs.UserMemoryCacheItem)) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authUser, err := helpers.GetAuthenticatedUser(ctx, app)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		if len(requiredFeatures) > 0 {
			for _, feature := range requiredFeatures {
				if !authUser.HasFeature(feature) {
					ctx.Redirect(http.StatusSeeOther, "/")
					return
				}
			}
		}

		handler(ctx, authUser)
	}
}
