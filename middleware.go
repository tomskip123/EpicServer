package EpicServer

import (
	"compress/gzip"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

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

	if !strings.Contains(ctx.GetHeader("Accept-Encoding"), "gzip") {
		ctx.Next()
		return
	}

	// Create a gzip writer
	gz := gzip.NewWriter(ctx.Writer)
	defer gz.Close()

	// Set the Content-Encoding header
	ctx.Header("Content-Encoding", "gzip")
	// Wrap the ResponseWriter with a gzip writer
	gzr := gzipResponseWriter{Writer: gz, ResponseWriter: ctx.Writer}
	ctx.Writer = gzr
	ctx.Next()
}

type gzipResponseWriter struct {
	gin.ResponseWriter
	Writer *gzip.Writer
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func CorsMiddleware(origins []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		origin := ctx.Request.Header.Get("Origin")

		if _, ok := ctx.Request.Header["Origin"]; ok {
			valid := false
			for _, v := range origins {
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

		for _, allowedOrigin := range origins {
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

func VerifyCSRFToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Bypass CSRF check for trusted sources or internal requests
		if IsTrustedSource(ctx.Request) {
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
