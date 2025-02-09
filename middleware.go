package EpicServer

import (
	"compress/gzip"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var gzipWriterPool = sync.Pool{
	New: func() interface{} {
		return gzip.NewWriter(nil)
	},
}

type gzipResponseWriter struct {
	gin.ResponseWriter
	Writer *gzip.Writer
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func CompressMiddleware(ctx *gin.Context) {
	// Check if the request is for an asset
	ext := strings.ToLower(filepath.Ext(ctx.Request.URL.Path))
	switch ext {
	case ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot":
		// Set Cache-Control header for assets
		ctx.Header("Cache-Control", "public, max-age=31536000")
	default:
		// Set Cache-Control header for non-asset requests
		ctx.Header("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0")
	}

	// Prevent compression for certain content types
	if ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".gif" || ext == ".svg" {
		ctx.Next()
		return
	}

	if !strings.Contains(ctx.GetHeader("Accept-Encoding"), "gzip") {
		ctx.Next()
		return
	}

	// Get a writer from the pool
	gz := gzipWriterPool.Get().(*gzip.Writer)
	gz.Reset(ctx.Writer)
	defer func() {
		gz.Close()
		gzipWriterPool.Put(gz)
	}()

	// Set the Content-Encoding header
	ctx.Header("Content-Encoding", "gzip")
	// Wrap the ResponseWriter with a gzip writer
	gzr := gzipResponseWriter{Writer: gz, ResponseWriter: ctx.Writer}
	ctx.Writer = gzr
	ctx.Next()
}

func CorsMiddleware(origins []string) gin.HandlerFunc {
	// Build a map for O(1) lookups.
	allowedOrigins := make(map[string]struct{})
	for _, origin := range origins {
		allowedOrigins[origin] = struct{}{}
	}
	return func(ctx *gin.Context) {
		origin := ctx.Request.Header.Get("Origin")
		if origin != "" {
			if _, ok := allowedOrigins[origin]; !ok {
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}
			ctx.Header("Access-Control-Allow-Origin", origin)
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

func WithCSRFProtection(cfg *SessionConfig) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if IsTrustedSource(ctx.Request) {
			ctx.Next()
			return
		}

		if ctx.Request.Method == http.MethodGet {
			token, err := GenerateCSRFToken()
			if err != nil {
				fmt.Printf("csrf_token_error: %v \n", err)
				ctx.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			ctx.SetCookie("csrf_token", token, cfg.CookieMaxAge, "/", cfg.CookieDomain, cfg.CookieSecure, cfg.CookieHTTPOnly)
			ctx.Set("csrf_token", token)
		}

		ctx.Next()
	}
}

func VerifyCSRFToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Allow safe HTTP methods to pass through without CSRF check
		if c.Request.Method == "GET" ||
			c.Request.Method == "HEAD" ||
			c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		// Get token from cookie
		cookie, err := c.Cookie("csrf_token")
		if err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Get token from header
		token := c.GetHeader("X-CSRF-Token")
		if token == "" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Verify tokens match
		if token != cookie {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		c.Next()
	}
}

func RemoveWWWMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.Host, "www.") {
			newHost := strings.TrimPrefix(c.Request.Host, "www.")
			newURL := c.Request.URL
			newURL.Host = newHost
			newURL.Scheme = "https"
			c.Redirect(http.StatusMovedPermanently, newURL.String())
			c.Abort()
			return
		}
		c.Next()
	}
}

type RateLimiter struct {
	mu     sync.Mutex
	tokens int
	max    int
	refill int
	ticker *time.Ticker
}

func NewRateLimiter(maxTokens, refillRate int, interval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		tokens: maxTokens,
		max:    maxTokens,
		refill: refillRate,
		ticker: time.NewTicker(interval),
	}
	go func() {
		for range rl.ticker.C {
			rl.mu.Lock()
			rl.tokens += rl.refill
			if rl.tokens > rl.max {
				rl.tokens = rl.max
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

func RateLimiterMiddleware(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rl.Allow() {
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
		c.Next()
	}
}

func RequestTimingMiddleware(logger Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start)
		logger.Info("Request ", c.Request.Method+" ", c.Request.URL.Path+" ", "took ", duration)
	}
}
