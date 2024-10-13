package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/cyberthy/server/helpers"
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

func init() {
	go cleanupVisitors()
}

func OtherSecurity(app *structs.App) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get the app struct from the context
		ctx.SetSameSite(http.SameSiteLaxMode)

		if len(app.Config.CSP) > 0 {
			ctx.Header("Content-Security-Policy", app.Config.CSP)
		}

		ctx.Next()
	}
}

func RequireJSONContentTypeOrHTMX(app *structs.App) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if ctx.ContentType() != "application/json" && !helpers.IsRequestFromHTMX(ctx) {
			ctx.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "NotXHR"})
			ctx.Abort()
			return
		}
		ctx.Next()
	}
}

var visitors = make(map[string]*rate.Limiter)
var mu sync.Mutex

// RateLimitMiddleware limits requests based on IP

// Get or create a rate limiter for each visitor

// Cleanup visitors that haven't been seen for a while
func cleanupVisitors() {
	for {
		time.Sleep(time.Minute)

		mu.Lock()
		for ip, limiter := range visitors {
			// Remove any visitor that hasn't been active for a while
			if limiter.AllowN(time.Now(), 1) {
				delete(visitors, ip)
			}
		}
		mu.Unlock()
	}
}
