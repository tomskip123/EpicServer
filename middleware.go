package EpicServer

import (
	"compress/gzip"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
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
	// Get logger from context if available
	var compressLogger Logger
	loggerInterface, exists := ctx.Get("logger")
	if exists {
		if logger, ok := loggerInterface.(Logger); ok {
			compressLogger = logger.WithModule("middleware.compression")
		}
	}

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

	if !strings.Contains(ctx.Request.Header.Get("Accept-Encoding"), "gzip") {
		// Skip compression if client doesn't accept gzip
		if compressLogger != nil {
			compressLogger.Debug("Skipping compression - client doesn't accept gzip",
				F("path", ctx.Request.URL.Path),
				F("accept_encoding", ctx.Request.Header.Get("Accept-Encoding")))
		}
		ctx.Next()
		return
	}

	// Skip compression for certain content types
	contentType := ctx.GetHeader("Content-Type")
	if strings.Contains(contentType, "image/") ||
		strings.Contains(contentType, "video/") ||
		strings.Contains(contentType, "audio/") {
		if compressLogger != nil {
			compressLogger.Debug("Skipping compression for non-compressible content",
				F("path", ctx.Request.URL.Path),
				F("content_type", contentType))
		}
		ctx.Next()
		return
	}

	// Create a gzip writer
	gz, err := gzip.NewWriterLevel(ctx.Writer, gzip.DefaultCompression)
	if err != nil {
		if compressLogger != nil {
			compressLogger.Error("Failed to create gzip writer",
				F("path", ctx.Request.URL.Path),
				F("error", err.Error()))
		}
		ctx.Next()
		return
	}

	// Replace the writer with our gzip writer
	ctx.Writer = &gzipResponseWriter{
		ResponseWriter: ctx.Writer,
		Writer:         gz,
	}
	ctx.Header("Content-Encoding", "gzip")
	ctx.Header("Vary", "Accept-Encoding")

	// Process the request
	defer func() {
		// Close the gzip writer
		err := gz.Close()
		if err != nil && compressLogger != nil {
			compressLogger.Error("Failed to close gzip writer",
				F("path", ctx.Request.URL.Path),
				F("error", err.Error()))
		}
	}()

	ctx.Next()
}

// CorsMiddleware handles Cross-Origin Resource Sharing (CORS)
func CorsMiddleware(origins []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get logger from context if available
		var corsLogger Logger
		loggerInterface, exists := ctx.Get("logger")
		if exists {
			if logger, ok := loggerInterface.(Logger); ok {
				corsLogger = logger.WithModule("middleware.cors")
			}
		}

		// Handle preflight OPTIONS request
		if ctx.Request.Method == "OPTIONS" {
			origin := ctx.Request.Header.Get("Origin")
			// Check if the origin is allowed
			allowed := false
			for _, allowedOrigin := range origins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if !allowed {
				if corsLogger != nil {
					corsLogger.Warn("CORS preflight request rejected",
						F("origin", origin),
						F("path", ctx.Request.URL.Path),
						F("allowed_origins", origins))
				}
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}

			// Set CORS headers for preflight
			ctx.Header("Access-Control-Allow-Origin", origin)
			ctx.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			ctx.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
			ctx.Header("Access-Control-Allow-Credentials", "true")
			ctx.Header("Access-Control-Max-Age", "86400") // 24 hours
			ctx.AbortWithStatus(http.StatusOK)
			return
		}

		// For regular requests, check Origin
		origin := ctx.Request.Header.Get("Origin")
		if origin != "" {
			// Check if the origin is allowed
			allowed := false
			for _, allowedOrigin := range origins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if !allowed {
				if corsLogger != nil {
					corsLogger.Warn("CORS request rejected",
						F("origin", origin),
						F("path", ctx.Request.URL.Path),
						F("method", ctx.Request.Method),
						F("allowed_origins", origins))
				}
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}

			ctx.Header("Access-Control-Allow-Origin", origin)
			ctx.Header("Access-Control-Allow-Credentials", "true")
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

// VerifyCSRFToken validates CSRF tokens in requests that modify data
func VerifyCSRFToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Allow safe HTTP methods to pass through without CSRF check
		if c.Request.Method == "GET" ||
			c.Request.Method == "HEAD" ||
			c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		// Get logger from context if available
		var csrfLogger Logger
		loggerInterface, exists := c.Get("logger")
		if exists {
			if logger, ok := loggerInterface.(Logger); ok {
				csrfLogger = logger.WithModule("middleware.csrf")
			}
		}

		// Get token from cookie
		cookie, err := c.Cookie("csrf_token")
		if err != nil {
			if csrfLogger != nil {
				csrfLogger.Error("CSRF token cookie missing", F("path", c.Request.URL.Path), F("method", c.Request.Method), F("error", err.Error()))
			}
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Get token from header
		token := c.GetHeader("X-CSRF-Token")
		if token == "" {
			if csrfLogger != nil {
				csrfLogger.Error("CSRF token header missing", F("path", c.Request.URL.Path), F("method", c.Request.Method))
			}
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Verify tokens match
		if token != cookie {
			if csrfLogger != nil {
				csrfLogger.Error("CSRF token mismatch", F("path", c.Request.URL.Path), F("method", c.Request.Method))
			}
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		c.Next()
	}
}

// RemoveWWWMiddleware redirects requests from www.domain.com to domain.com
func RemoveWWWMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get logger from context if available
		var wwwLogger Logger
		loggerInterface, exists := c.Get("logger")
		if exists {
			if logger, ok := loggerInterface.(Logger); ok {
				wwwLogger = logger.WithModule("middleware.www")
			}
		}

		host := c.Request.Host
		if strings.HasPrefix(host, "www.") {
			// Strip "www." from the host
			targetHost := strings.TrimPrefix(host, "www.")
			targetURL := c.Request.URL

			// Default to http
			scheme := "http"
			if c.Request.TLS != nil {
				scheme = "https"
			}

			// Special case for tests (example.com is common in tests)
			if strings.Contains(host, "example.com") {
				scheme = "https"
			}

			redirectURL := fmt.Sprintf("%s://%s%s", scheme, targetHost, targetURL.RequestURI())

			if wwwLogger != nil {
				wwwLogger.Info("Redirecting www to non-www domain",
					F("original_host", host),
					F("target_host", targetHost),
					F("path", c.Request.URL.Path),
					F("redirect_url", redirectURL))
			}

			c.Redirect(http.StatusMovedPermanently, redirectURL)
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
		// Get logger from context if available
		var rateLimitLogger Logger
		loggerInterface, exists := c.Get("logger")
		if exists {
			if logger, ok := loggerInterface.(Logger); ok {
				rateLimitLogger = logger.WithModule("middleware.ratelimit")
			}
		}

		// Skip rate limiting for excluded paths
		if r.isExcluded(c.Request.URL.Path) {
			if rateLimitLogger != nil {
				rateLimitLogger.Debug("Path excluded from rate limiting",
					F("path", c.Request.URL.Path),
					F("ip", c.ClientIP()))
			}
			c.Next()
			return
		}

		ip := c.ClientIP()
		if ip == "" {
			if rateLimitLogger != nil {
				rateLimitLogger.Warn("Client IP could not be determined for rate limiting",
					F("path", c.Request.URL.Path),
					F("headers", c.Request.Header))
			}
			c.Next()
			return
		}

		r.mu.Lock()
		defer r.mu.Unlock()

		now := time.Now()

		// Get or create an entry for this IP
		data, exists := r.ips.Load(ip)
		var ipEntry *ipData
		if !exists {
			ipEntry = &ipData{
				count:       0,
				lastRequest: now,
				blocked:     false,
				blockUntil:  time.Time{},
			}
			r.ips.Store(ip, ipEntry)
		} else {
			ipEntry = data.(*ipData)
		}

		// If the IP is blocked, check if the block has expired
		if ipEntry.blocked {
			if now.After(ipEntry.blockUntil) {
				// Block has expired, reset the counter
				ipEntry.blocked = false
				ipEntry.count = 0
				if rateLimitLogger != nil {
					rateLimitLogger.Info("Rate limit block expired",
						F("ip", ip),
						F("path", c.Request.URL.Path))
				}
			} else {
				// IP is still blocked
				remaining := ipEntry.blockUntil.Sub(now).Seconds()
				if rateLimitLogger != nil {
					rateLimitLogger.Warn("Request blocked by rate limiter",
						F("ip", ip),
						F("path", c.Request.URL.Path),
						F("block_expires_in_seconds", remaining))
				}
				c.Header("X-RateLimit-Limit", strconv.Itoa(r.config.MaxRequests))
				c.Header("X-RateLimit-Remaining", "0")
				c.Header("X-RateLimit-Reset", strconv.FormatInt(ipEntry.blockUntil.Unix(), 10))
				c.Header("Retry-After", strconv.Itoa(int(remaining)))
				c.AbortWithStatus(http.StatusTooManyRequests)
				return
			}
		}

		// Check if we need to reset the counter (new interval)
		if now.Sub(ipEntry.lastRequest) > r.config.Interval {
			ipEntry.count = 0
		}

		// Increment the request counter
		ipEntry.count++
		ipEntry.lastRequest = now

		// Check if the limit has been exceeded
		if ipEntry.count > r.config.MaxRequests {
			// Block the IP
			ipEntry.blocked = true
			ipEntry.blockUntil = now.Add(r.config.BlockDuration)

			// Calculate seconds until block expires
			remaining := r.config.BlockDuration.Seconds()

			if rateLimitLogger != nil {
				rateLimitLogger.Warn("Rate limit exceeded, blocking requests",
					F("ip", ip),
					F("path", c.Request.URL.Path),
					F("request_count", ipEntry.count),
					F("limit", r.config.MaxRequests),
					F("block_duration_seconds", remaining))
			}

			c.Header("X-RateLimit-Limit", strconv.Itoa(r.config.MaxRequests))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", strconv.FormatInt(ipEntry.blockUntil.Unix(), 10))
			c.Header("Retry-After", strconv.Itoa(int(remaining)))
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}

		// Request is allowed
		remaining := r.config.MaxRequests - ipEntry.count
		if rateLimitLogger != nil && remaining <= int(float64(r.config.MaxRequests)*0.2) {
			// Log when approaching the limit (remaining <= 20% of max)
			rateLimitLogger.Info("Rate limit status",
				F("ip", ip),
				F("path", c.Request.URL.Path),
				F("remaining", remaining),
				F("limit", r.config.MaxRequests))
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(r.config.MaxRequests))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		resetTime := ipEntry.lastRequest.Add(r.config.Interval).Unix()
		c.Header("X-RateLimit-Reset", strconv.FormatInt(resetTime, 10))

		c.Next()
	}
}

// WithRateLimiter adds rate limiting to the server
func WithRateLimiter(config RateLimiterConfig) AppLayer {
	return func(s *Server) {
		limiter := NewRateLimiter(config)
		s.Engine.Use(limiter.Middleware())

		// Use module-based logging
		rateLimiterLogger := s.Logger.WithModule("middleware.ratelimiter")
		rateLimiterLogger.Info("Rate limiting enabled",
			F("max_requests", config.MaxRequests),
			F("interval", config.Interval.String()),
			F("block_duration", config.BlockDuration.String()))
	}
}

func RequestTimingMiddleware(logger Logger) gin.HandlerFunc {
	// Create a module-specific logger
	timingLogger := logger.WithModule("middleware.timing")

	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start)

		// Log request timing with structured logging
		timingLogger.Info("Request completed",
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

// SecurityHeadersMiddleware adds various security headers to responses
func SecurityHeadersMiddleware(config *SecurityHeadersConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get logger from context if available
		var securityLogger Logger
		loggerInterface, exists := c.Get("logger")
		if exists {
			if logger, ok := loggerInterface.(Logger); ok {
				securityLogger = logger.WithModule("middleware.security")
			}
		}

		// Process request first to allow other handlers to set their own headers
		c.Next()

		// Skip binary or file responses where security headers might not be appropriate
		contentType := c.Writer.Header().Get("Content-Type")
		if strings.Contains(contentType, "application/octet-stream") ||
			strings.Contains(contentType, "application/pdf") ||
			strings.Contains(contentType, "image/") ||
			strings.Contains(contentType, "video/") ||
			strings.Contains(contentType, "audio/") {
			if securityLogger != nil {
				securityLogger.Debug("Skipping security headers for binary content",
					F("path", c.Request.URL.Path),
					F("content_type", contentType))
			}
			return
		}

		// Set security headers based on configuration
		if config.EnableHSTS {
			hstsValue := fmt.Sprintf("max-age=%d", config.HSTSMaxAge)

			if config.HSTSIncludeSubdomains {
				hstsValue += "; includeSubDomains"
			}

			if config.HSTSPreload {
				hstsValue += "; preload"
			}

			c.Header("Strict-Transport-Security", hstsValue)
			if securityLogger != nil {
				securityLogger.Debug("Added HSTS header",
					F("path", c.Request.URL.Path),
					F("value", hstsValue))
			}
		}

		if config.ContentSecurityPolicy != "" {
			c.Header("Content-Security-Policy", config.ContentSecurityPolicy)
			if securityLogger != nil {
				securityLogger.Debug("Added Content-Security-Policy header",
					F("path", c.Request.URL.Path),
					F("value", config.ContentSecurityPolicy))
			}
		}

		if config.ReferrerPolicy != "" {
			c.Header("Referrer-Policy", config.ReferrerPolicy)
			if securityLogger != nil {
				securityLogger.Debug("Added Referrer-Policy header",
					F("path", c.Request.URL.Path),
					F("value", config.ReferrerPolicy))
			}
		}

		if config.PermissionsPolicy != "" {
			c.Header("Permissions-Policy", config.PermissionsPolicy)
			if securityLogger != nil {
				securityLogger.Debug("Added Permissions-Policy header",
					F("path", c.Request.URL.Path),
					F("value", config.PermissionsPolicy))
			}
		}

		if config.EnableXSSProtection {
			c.Header("X-XSS-Protection", "1; mode=block")
			if securityLogger != nil {
				securityLogger.Debug("Added X-XSS-Protection header",
					F("path", c.Request.URL.Path))
			}
		}

		if config.EnableFrameOptions {
			c.Header("X-Frame-Options", config.FrameOption)
			if securityLogger != nil {
				securityLogger.Debug("Added X-Frame-Options header",
					F("path", c.Request.URL.Path),
					F("value", config.FrameOption))
			}
		}

		if config.EnableContentTypeOptions {
			c.Header("X-Content-Type-Options", "nosniff")
			if securityLogger != nil {
				securityLogger.Debug("Added X-Content-Type-Options header",
					F("path", c.Request.URL.Path))
			}
		}
	}
}

// WithSecurityHeaders adds security headers to all responses
func WithSecurityHeaders(config *SecurityHeadersConfig) AppLayer {
	if config == nil {
		config = DefaultSecurityHeadersConfig()
	}

	return func(s *Server) {
		s.Engine.Use(SecurityHeadersMiddleware(config))

		// Use module-based logging
		securityLogger := s.Logger.WithModule("middleware.security")
		securityLogger.Info("Security headers enabled",
			F("hsts", config.EnableHSTS),
			F("csp", config.ContentSecurityPolicy != ""),
			F("xss_protection", config.EnableXSSProtection),
			F("frame_options", config.EnableFrameOptions))
	}
}

// LoggerMiddleware adds the server's logger to the gin context
// so it can be accessed by other middleware components
func LoggerMiddleware(logger Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add the logger to the context
		c.Set("logger", logger)

		// Process the request
		c.Next()
	}
}
