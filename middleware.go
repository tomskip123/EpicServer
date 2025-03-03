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

// RateLimiterConfig configures the rate limiter
type RateLimiterConfig struct {
	// MaxRequests is the maximum number of requests allowed per IP per interval
	MaxRequests int
	// Interval is the time window to track requests
	Interval time.Duration
	// BlockDuration is how long to block requests after the limit is reached
	BlockDuration time.Duration
	// ExcludedPaths are paths that won't be rate limited
	ExcludedPaths []string
}

type ipData struct {
	count       int
	lastRequest time.Time
	blocked     bool
	blockUntil  time.Time
}

// RateLimiter implements IP-based request rate limiting
type RateLimiter struct {
	config RateLimiterConfig
	ips    sync.Map
	mu     sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config RateLimiterConfig) *RateLimiter {
	// Set default values if not provided
	if config.MaxRequests <= 0 {
		config.MaxRequests = 100
	}
	if config.Interval <= 0 {
		config.Interval = time.Minute
	}
	if config.BlockDuration <= 0 {
		config.BlockDuration = 5 * time.Minute
	}

	// Create excluded paths map for O(1) lookups
	limiter := &RateLimiter{
		config: config,
	}

	// Start cleanup goroutine
	go limiter.cleanup()

	return limiter
}

// cleanup periodically removes old IP data
func (r *RateLimiter) cleanup() {
	ticker := time.NewTicker(r.config.Interval)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		r.ips.Range(func(key, value interface{}) bool {
			data := value.(*ipData)

			// If IP is blocked but block time has expired, remove the block
			if data.blocked && now.After(data.blockUntil) {
				r.ips.Delete(key)
				return true
			}

			// If IP has not made a request in 2 intervals, remove it
			if now.Sub(data.lastRequest) > 2*r.config.Interval {
				r.ips.Delete(key)
			}

			return true
		})
	}
}

// isExcluded checks if a path is excluded from rate limiting
func (r *RateLimiter) isExcluded(path string) bool {
	for _, excludedPath := range r.config.ExcludedPaths {
		if excludedPath == path || (strings.HasSuffix(excludedPath, "*") &&
			strings.HasPrefix(path, excludedPath[:len(excludedPath)-1])) {
			return true
		}
	}
	return false
}

// Middleware returns a Gin middleware function for rate limiting
func (r *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip rate limiting for excluded paths
		if r.isExcluded(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Get client IP
		ip := c.ClientIP()
		if ip == "" {
			ip = c.Request.RemoteAddr
		}

		now := time.Now()

		// Check if IP is in the map
		val, ok := r.ips.Load(ip)
		if !ok {
			// First request from this IP
			r.ips.Store(ip, &ipData{
				count:       1,
				lastRequest: now,
				blocked:     false,
			})
			c.Next()
			return
		}

		data := val.(*ipData)

		// Check if IP is blocked
		if data.blocked {
			if now.After(data.blockUntil) {
				// Block has expired, reset
				data.blocked = false
				data.count = 1
				data.lastRequest = now
				c.Next()
			} else {
				// Still blocked
				c.Header("Retry-After", fmt.Sprintf("%d", int(data.blockUntil.Sub(now).Seconds())))
				c.AbortWithStatus(http.StatusTooManyRequests)
			}
			return
		}

		// Check if we're still in the current interval
		if now.Sub(data.lastRequest) > r.config.Interval {
			// Reset for new interval
			data.count = 1
			data.lastRequest = now
			c.Next()
			return
		}

		// Increment request count
		data.count++
		data.lastRequest = now

		// Check if limit exceeded
		if data.count > r.config.MaxRequests {
			data.blocked = true
			data.blockUntil = now.Add(r.config.BlockDuration)
			c.Header("Retry-After", fmt.Sprintf("%d", int(r.config.BlockDuration.Seconds())))
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}

		// Within limits
		c.Next()
	}
}

// WithRateLimiter adds rate limiting to the server
func WithRateLimiter(config RateLimiterConfig) AppLayer {
	return func(s *Server) {
		limiter := NewRateLimiter(config)
		s.Engine.Use(limiter.Middleware())
		s.Logger.Info("Rate limiting enabled",
			F("max_requests", config.MaxRequests),
			F("interval", config.Interval.String()),
			F("block_duration", config.BlockDuration.String()))
	}
}

func RequestTimingMiddleware(logger Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start)

		// Log request timing with structured logging
		logger.Info("Request completed",
			F("method", c.Request.Method),
			F("path", c.Request.URL.Path),
			F("duration_ms", duration.Milliseconds()),
			F("status", c.Writer.Status()))
	}
}

// SecurityHeadersConfig configures security headers
type SecurityHeadersConfig struct {
	// EnableHSTS enables HTTP Strict Transport Security
	EnableHSTS bool
	// HSTSMaxAge is the max age in seconds for HSTS
	HSTSMaxAge int
	// HSTSIncludeSubdomains includes subdomains in HSTS
	HSTSIncludeSubdomains bool
	// HSTSPreload adds preload directive to HSTS
	HSTSPreload bool
	// ContentSecurityPolicy sets the Content-Security-Policy header
	ContentSecurityPolicy string
	// ReferrerPolicy sets the Referrer-Policy header
	ReferrerPolicy string
	// PermissionsPolicy sets the Permissions-Policy header
	PermissionsPolicy string
	// EnableXSSProtection enables X-XSS-Protection header
	EnableXSSProtection bool
	// EnableFrameOptions enables X-Frame-Options header
	EnableFrameOptions bool
	// FrameOption sets the X-Frame-Options value
	FrameOption string
	// EnableContentTypeOptions enables X-Content-Type-Options header
	EnableContentTypeOptions bool
}

// DefaultSecurityHeadersConfig returns a config with recommended security settings
func DefaultSecurityHeadersConfig() *SecurityHeadersConfig {
	return &SecurityHeadersConfig{
		EnableHSTS:               true,
		HSTSMaxAge:               31536000, // 1 year
		HSTSIncludeSubdomains:    true,
		HSTSPreload:              false,
		ContentSecurityPolicy:    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'",
		ReferrerPolicy:           "strict-origin-when-cross-origin",
		PermissionsPolicy:        "camera=(), microphone=(), geolocation=(), payment=()",
		EnableXSSProtection:      true,
		EnableFrameOptions:       true,
		FrameOption:              "DENY",
		EnableContentTypeOptions: true,
	}
}

// SecurityHeadersMiddleware adds security headers to all responses
func SecurityHeadersMiddleware(config *SecurityHeadersConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add Content-Security-Policy header
		if config.ContentSecurityPolicy != "" {
			c.Header("Content-Security-Policy", config.ContentSecurityPolicy)
		}

		// Add Strict-Transport-Security header
		if config.EnableHSTS {
			hstsValue := fmt.Sprintf("max-age=%d", config.HSTSMaxAge)
			if config.HSTSIncludeSubdomains {
				hstsValue += "; includeSubDomains"
			}
			if config.HSTSPreload {
				hstsValue += "; preload"
			}
			c.Header("Strict-Transport-Security", hstsValue)
		}

		// Add Referrer-Policy header
		if config.ReferrerPolicy != "" {
			c.Header("Referrer-Policy", config.ReferrerPolicy)
		}

		// Add Permissions-Policy header
		if config.PermissionsPolicy != "" {
			c.Header("Permissions-Policy", config.PermissionsPolicy)
		}

		// Add X-XSS-Protection header
		if config.EnableXSSProtection {
			c.Header("X-XSS-Protection", "1; mode=block")
		}

		// Add X-Frame-Options header
		if config.EnableFrameOptions {
			c.Header("X-Frame-Options", config.FrameOption)
		}

		// Add X-Content-Type-Options header
		if config.EnableContentTypeOptions {
			c.Header("X-Content-Type-Options", "nosniff")
		}

		c.Next()
	}
}

// WithSecurityHeaders adds security headers to all responses
func WithSecurityHeaders(config *SecurityHeadersConfig) AppLayer {
	if config == nil {
		config = DefaultSecurityHeadersConfig()
	}

	return func(s *Server) {
		s.Engine.Use(SecurityHeadersMiddleware(config))
		s.Logger.Info("Security headers enabled", F("hsts", config.EnableHSTS))
	}
}
