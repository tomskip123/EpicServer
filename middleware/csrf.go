package middleware

import (
	"fmt"
	"net/http"

	"github.com/cyberthy/server/services"
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
)

func SetCSRFCookie(app *structs.App) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		csrfToken, err := services.GenerateCSRFToken()
		if err != nil {
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		ctx.SetCookie(
			"csrf_token", // this could be part of app struct
			csrfToken,
			3600,                    // this could be part of app struct
			"/",                     // this could be part of app struct
			app.Config.CookieDomain, // this could be part of app struct
			app.Config.CookieSecure, // this could be part of app struct
			true,
		)
		ctx.Next()
	}
}

func VerifyCSRFToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Bypass CSRF check for trusted sources or internal requests
		if services.IsTrustedSource(ctx.Request) {
			ctx.Next()
			return
		}

		_, exists := ctx.Get("auth_user")
		if !exists {
			ctx.Next()
			return
		}

		if ctx.Request.Method != http.MethodGet {
			csrfCookie, err := ctx.Cookie("csrf_token")
			if err != nil {
				fmt.Printf("csrf_token_error: %v \n", err)
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}

			csrfToken := ctx.GetHeader("X-CSRF-Token")
			if csrfToken == "" {
				csrfToken = ctx.PostForm("csrf_token")
			}

			if csrfToken != csrfCookie {
				fmt.Printf("csrf_token_not_equal_to_cookie: %v \n", err)
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}
		}

		ctx.Next()
	}
}
