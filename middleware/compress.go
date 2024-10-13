package middleware

import (
	"compress/gzip"
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
