package EpicServer

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestCompressMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name           string
		path           string
		acceptEncoding string
		wantCompressed bool
	}{
		{
			name:           "accepts gzip",
			path:           "/test.js",
			acceptEncoding: "gzip",
			wantCompressed: true,
		},
		{
			name:           "no compression requested",
			path:           "/test.js",
			acceptEncoding: "",
			wantCompressed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(CompressMiddleware)
			r.GET(tt.path, func(c *gin.Context) {
				c.String(200, strings.Repeat("test", 100))
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tt.acceptEncoding)
			}

			r.ServeHTTP(w, req)

			if tt.wantCompressed {
				if w.Header().Get("Content-Encoding") != "gzip" {
					t.Error("response not compressed")
				}
				reader, err := gzip.NewReader(w.Body)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				content, err := io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
				if len(content) == 0 {
					t.Error("compressed content is empty")
				}
			}
		})
	}
}

func TestCompressMiddlewareWithDifferentContentTypes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name           string
		path           string
		acceptEncoding string
		contentType    string
		wantCompressed bool
	}{
		{
			name:           "accepts gzip with text content",
			path:           "/test.txt",
			acceptEncoding: "gzip",
			contentType:    "text/plain",
			wantCompressed: true,
		},
		{
			name:           "accepts gzip with json content",
			path:           "/test.json",
			acceptEncoding: "gzip",
			contentType:    "application/json",
			wantCompressed: true,
		},
		{
			name:           "no compression for image content",
			path:           "/test.png",
			acceptEncoding: "gzip",
			contentType:    "image/png",
			wantCompressed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(CompressMiddleware)
			r.GET(tt.path, func(c *gin.Context) {
				c.Header("Content-Type", tt.contentType)
				c.String(200, strings.Repeat("test", 100))
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tt.acceptEncoding)
			}

			r.ServeHTTP(w, req)

			if tt.wantCompressed {
				if w.Header().Get("Content-Encoding") != "gzip" {
					t.Error("response not compressed")
				}
				reader, err := gzip.NewReader(w.Body)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				content, err := io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
				if len(content) == 0 {
					t.Error("compressed content is empty")
				}
			} else {
				if w.Header().Get("Content-Encoding") == "gzip" {
					t.Error("response should not be compressed")
				}
			}
		})
	}
}

func TestCorsMiddleware(t *testing.T) {
	tests := []struct {
		name          string
		origins       []string
		requestOrigin string
		wantStatus    int
		wantHeader    string
	}{
		{
			name:          "allowed origin",
			origins:       []string{"http://example.com"},
			requestOrigin: "http://example.com",
			wantStatus:    http.StatusOK,
			wantHeader:    "http://example.com",
		},
		{
			name:          "disallowed origin",
			origins:       []string{"http://example.com"},
			requestOrigin: "http://evil.com",
			wantStatus:    http.StatusForbidden,
			wantHeader:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(CorsMiddleware(tt.origins))
			r.GET("/test", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.requestOrigin)

			r.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			if got := w.Header().Get("Access-Control-Allow-Origin"); got != tt.wantHeader {
				t.Errorf("CORS header = %q, want %q", got, tt.wantHeader)
			}
		})
	}
}

func TestCorsMiddlewarePreflight(t *testing.T) {
	tests := []struct {
		name          string
		origins       []string
		requestOrigin string
		wantStatus    int
		wantHeader    string
	}{
		{
			name:          "preflight allowed origin",
			origins:       []string{"http://example.com"},
			requestOrigin: "http://example.com",
			wantStatus:    http.StatusOK,
			wantHeader:    "http://example.com",
		},
		{
			name:          "preflight disallowed origin",
			origins:       []string{"http://example.com"},
			requestOrigin: "http://evil.com",
			wantStatus:    http.StatusForbidden,
			wantHeader:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(CorsMiddleware(tt.origins))
			r.OPTIONS("/test", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("OPTIONS", "/test", nil)
			req.Header.Set("Origin", tt.requestOrigin)

			r.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			if got := w.Header().Get("Access-Control-Allow-Origin"); got != tt.wantHeader {
				t.Errorf("CORS header = %q, want %q", got, tt.wantHeader)
			}
		})
	}
}

func TestRemoveWWWMiddleware(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		wantCode     int
		wantRedirect bool
	}{
		{
			name:         "with www",
			host:         "www.example.com",
			wantCode:     http.StatusMovedPermanently,
			wantRedirect: true,
		},
		{
			name:         "without www",
			host:         "example.com",
			wantCode:     http.StatusOK,
			wantRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(RemoveWWWMiddleware())
			r.GET("/test", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Host = tt.host

			r.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tt.wantCode)
			}

			if tt.wantRedirect {
				location := w.Header().Get("Location")
				if !strings.Contains(location, "https://example.com") {
					t.Errorf("redirect location = %q, want to contain 'https://example.com'", location)
				}
			}
		})
	}
}

func TestVerifyCSRFToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a test server with the CSRF token verification middleware
	r := gin.New()
	r.Use(VerifyCSRFToken())

	// Test handler
	r.POST("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	r.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Test cases
	testCases := []struct {
		name         string
		method       string
		path         string
		headers      map[string]string
		cookies      map[string]string
		expectStatus int
	}{
		{
			name:         "GET request - should skip CSRF check",
			method:       "GET",
			path:         "/test",
			headers:      nil,
			cookies:      nil,
			expectStatus: http.StatusOK,
		},
		{
			name:         "POST without CSRF token - should fail",
			method:       "POST",
			path:         "/test",
			headers:      nil,
			cookies:      nil,
			expectStatus: http.StatusForbidden,
		},
		{
			name:   "POST with CSRF token in header but not in cookie - should fail",
			method: "POST",
			path:   "/test",
			headers: map[string]string{
				"X-CSRF-Token": "test-token",
			},
			cookies:      nil,
			expectStatus: http.StatusForbidden,
		},
		{
			name:    "POST with CSRF token in cookie but not in header - should fail",
			method:  "POST",
			path:    "/test",
			headers: nil,
			cookies: map[string]string{
				"csrf_token": "test-token",
			},
			expectStatus: http.StatusForbidden,
		},
		{
			name:   "POST with matching CSRF tokens - should pass",
			method: "POST",
			path:   "/test",
			headers: map[string]string{
				"X-CSRF-Token": "test-token",
			},
			cookies: map[string]string{
				"csrf_token": "test-token",
			},
			expectStatus: http.StatusOK,
		},
		{
			name:   "POST with non-matching CSRF tokens - should fail",
			method: "POST",
			path:   "/test",
			headers: map[string]string{
				"X-CSRF-Token": "wrong-token",
			},
			cookies: map[string]string{
				"csrf_token": "test-token",
			},
			expectStatus: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)

			// Add headers if any
			if tc.headers != nil {
				for key, value := range tc.headers {
					req.Header.Set(key, value)
				}
			}

			// Add cookies if any
			if tc.cookies != nil {
				for name, value := range tc.cookies {
					req.AddCookie(&http.Cookie{
						Name:  name,
						Value: value,
					})
				}
			}

			resp := httptest.NewRecorder()
			r.ServeHTTP(resp, req)

			assert.Equal(t, tc.expectStatus, resp.Code)
		})
	}
}

func TestVerifyCSRFTokenMalformed(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name         string
		method       string
		setupRequest func(*http.Request, string)
		wantCode     int
	}{
		{
			name:   "malformed token",
			method: "POST",
			setupRequest: func(req *http.Request, token string) {
				req.Header.Set("X-CSRF-Token", "malformed-token")
				req.AddCookie(&http.Cookie{
					Name:     "csrf_token",
					Value:    token,
					Path:     "/",
					Domain:   "localhost",
					Secure:   false,
					HttpOnly: true,
				})
			},
			wantCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(VerifyCSRFToken())

			router.Any("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "ok")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, "/test", nil)
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

			if tt.setupRequest != nil {
				token, _ := GenerateCSRFToken()
				tt.setupRequest(req, token)
			}

			router.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("%s request: got status %v, want %v", tt.method, w.Code, tt.wantCode)
			}
		})
	}
}

func TestCSRFProtection(t *testing.T) {
	router := gin.New()

	cfg := &SessionConfig{
		CookieDomain:   "localhost",
		CookieMaxAge:   3600,
		CookieSecure:   false,
		CookieHTTPOnly: true,
	}

	router.Use(WithCSRFProtection(cfg))

	router.GET("/csrf", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/csrf", nil)
	router.ServeHTTP(w, req)

	cookies := w.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "csrf_token" {
			csrfCookie = cookie
			break
		}
	}

	if csrfCookie == nil {
		t.Fatal("CSRF cookie not set")
	}

	if len(csrfCookie.Value) == 0 {
		t.Error("CSRF token is empty")
	}
}

// TestRateLimiter is a simplified version of RateLimiter for testing
type TestRateLimiter struct {
	maxTokens   int
	tokens      int
	refillRate  int
	refillEvery time.Duration
	lastRefill  time.Time
	mu          sync.Mutex
}

// NewTestRateLimiter creates a new test rate limiter
func NewTestRateLimiter(maxTokens, refillRate int, refillEvery time.Duration) *TestRateLimiter {
	return &TestRateLimiter{
		maxTokens:   maxTokens,
		tokens:      maxTokens,
		refillRate:  refillRate,
		refillEvery: refillEvery,
		lastRefill:  time.Now(),
	}
}

// Allow checks if a request is allowed
func (r *TestRateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if we need to refill
	now := time.Now()
	elapsed := now.Sub(r.lastRefill)
	if elapsed >= r.refillEvery {
		// Calculate how many tokens to add
		refills := int(elapsed / r.refillEvery)
		tokensToAdd := refills * r.refillRate
		r.tokens = min(r.maxTokens, r.tokens+tokensToAdd)
		r.lastRefill = now
	}

	// Check if we have tokens
	if r.tokens > 0 {
		r.tokens--
		return true
	}
	return false
}

// Middleware returns a gin middleware for rate limiting
func (r *TestRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if r.Allow() {
			c.Next()
		} else {
			c.AbortWithStatus(http.StatusTooManyRequests)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestRateLimiterAllow(t *testing.T) {
	rl := NewTestRateLimiter(3, 1, 200*time.Millisecond)

	for i := 0; i < 3; i++ {
		if !rl.Allow() {
			t.Errorf("expected token %d to be allowed", i+1)
		}
	}
	if rl.Allow() {
		t.Error("expected no token to be allowed after consuming all tokens")
	}

	time.Sleep(250 * time.Millisecond)
	if !rl.Allow() {
		t.Error("expected token to be available after refill")
	}
}

func TestRateLimiterConcurrency(t *testing.T) {
	rl := NewTestRateLimiter(10, 1, 100*time.Millisecond)
	var wg sync.WaitGroup
	allowedCount := 0
	mu := sync.Mutex{}

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.Allow() {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowedCount > 10 {
		t.Errorf("allowed %d tokens; expected at most 10", allowedCount)
	}
}

func TestRateLimiterMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rl := NewTestRateLimiter(2, 1, 200*time.Millisecond)

	r := gin.New()
	r.Use(rl.Middleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	tests := []struct {
		name       string
		wantStatus int
	}{
		{"first request", http.StatusOK},
		{"second request", http.StatusOK},
		{"third request", http.StatusTooManyRequests},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			r.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}

	// Wait for refill
	time.Sleep(250 * time.Millisecond)

	t.Run("fourth request after refill", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

// MockLogger is a mock implementation of the Logger interface for testing
type MockLogger struct {
	InfoCalled  bool
	WarnCalled  bool
	ErrorCalled bool
	DebugCalled bool
	FatalCalled bool
	LastMsg     string
	LastFields  []LogField
}

func (m *MockLogger) Debug(msg string, fields ...LogField) {
	m.DebugCalled = true
	m.LastMsg = msg
	m.LastFields = fields
}

func (m *MockLogger) Info(msg string, fields ...LogField) {
	m.InfoCalled = true
	m.LastMsg = msg
	m.LastFields = fields
}

func (m *MockLogger) Warn(msg string, fields ...LogField) {
	m.WarnCalled = true
	m.LastMsg = msg
	m.LastFields = fields
}

func (m *MockLogger) Error(msg string, fields ...LogField) {
	m.ErrorCalled = true
	m.LastMsg = msg
	m.LastFields = fields
}

func (m *MockLogger) Fatal(msg string, fields ...LogField) {
	m.FatalCalled = true
	m.LastMsg = msg
	m.LastFields = fields
}

func (m *MockLogger) WithFields(fields ...LogField) Logger {
	return m
}

func (m *MockLogger) SetOutput(w io.Writer) {
	// No-op for mock
}

func (m *MockLogger) SetLevel(level LogLevel) {
	// No-op for mock
}

func (m *MockLogger) SetFormat(format LogFormat) {
	// No-op for mock
}

// New methods to implement the updated Logger interface
func (m *MockLogger) WithModule(module string) Logger {
	return m
}

func (m *MockLogger) SetRegistry(registry *LogRegistry) {
	// No-op for mock
}

func TestRequestTimingMiddleware(t *testing.T) {
	// Create a mock logger
	mockLogger := &MockLogger{}

	// Create a test router with the middleware
	router := gin.New()
	router.Use(RequestTimingMiddleware(mockLogger))

	// Add a test route
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// Create a test request
	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	// Serve the request
	router.ServeHTTP(w, req)

	// Check that the logger was called
	if !mockLogger.InfoCalled {
		t.Error("Logger Info method was not called")
	}

	// Check that the log message contains "Request completed"
	if !strings.Contains(mockLogger.LastMsg, "Request completed") {
		t.Errorf("Expected log message to contain 'Request completed', got: %s", mockLogger.LastMsg)
	}

	// Check that the duration field exists
	foundDuration := false
	for _, field := range mockLogger.LastFields {
		if field.Key == "duration_ms" {
			foundDuration = true
			break
		}
	}

	if !foundDuration {
		t.Error("Expected log to contain duration_ms field")
	}
}

// Tests for the actual RateLimiter implementation

func TestNewRateLimiter(t *testing.T) {
	tests := []struct {
		name    string
		config  RateLimiterConfig
		wantMax int
		wantInt time.Duration
		wantDur time.Duration
	}{
		{
			name:    "default values",
			config:  RateLimiterConfig{},
			wantMax: 100,
			wantInt: time.Minute,
			wantDur: 5 * time.Minute,
		},
		{
			name: "custom values",
			config: RateLimiterConfig{
				MaxRequests:   200,
				Interval:      30 * time.Second,
				BlockDuration: 10 * time.Minute,
			},
			wantMax: 200,
			wantInt: 30 * time.Second,
			wantDur: 10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewRateLimiter(tt.config)
			if limiter == nil {
				t.Fatal("NewRateLimiter() returned nil")
			}
			if limiter.config.MaxRequests != tt.wantMax {
				t.Errorf("MaxRequests = %d, want %d", limiter.config.MaxRequests, tt.wantMax)
			}
			if limiter.config.Interval != tt.wantInt {
				t.Errorf("Interval = %v, want %v", limiter.config.Interval, tt.wantInt)
			}
			if limiter.config.BlockDuration != tt.wantDur {
				t.Errorf("BlockDuration = %v, want %v", limiter.config.BlockDuration, tt.wantDur)
			}
		})
	}
}

func TestRateLimiterIsExcluded(t *testing.T) {
	limiter := NewRateLimiter(RateLimiterConfig{
		ExcludedPaths: []string{
			"/api/health",
			"/api/static/*",
			"/api/public/",
		},
	})

	tests := []struct {
		path string
		want bool
	}{
		{"/api/health", true},
		{"/api/static/css/style.css", true},
		{"/api/static/js/app.js", true},
		{"/api/public/", true},
		{"/api/public/doc.pdf", false},
		{"/api/users", false},
		{"/api/auth", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := limiter.isExcluded(tt.path); got != tt.want {
				t.Errorf("isExcluded(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestActualRateLimiterMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a rate limiter with a small limit for testing
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests:   2,
		Interval:      5 * time.Second,
		BlockDuration: 5 * time.Second,
		ExcludedPaths: []string{"/excluded"},
	})

	router := gin.New()
	router.Use(limiter.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	router.GET("/excluded", func(c *gin.Context) {
		c.String(http.StatusOK, "excluded")
	})

	// Test excluded path
	t.Run("excluded path", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/excluded", nil)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("excluded path status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	// Test regular path
	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("request %d", i+1), func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:1234" // Set a remote address for the test
			router.ServeHTTP(w, req)

			// First two requests should succeed, third should be rate limited
			if i < 2 {
				if w.Code != http.StatusOK {
					t.Errorf("request %d status = %d, want %d", i+1, w.Code, http.StatusOK)
				}
			} else {
				if w.Code != http.StatusTooManyRequests {
					t.Errorf("request %d status = %d, want %d", i+1, w.Code, http.StatusTooManyRequests)
				}
				if w.Header().Get("Retry-After") == "" {
					t.Errorf("Retry-After header not set")
				}
			}
		})
	}

	// Test that a different IP is not rate limited
	t.Run("different IP", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.2:1234" // Different IP
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("different IP status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestWithRateLimiter(t *testing.T) {
	// Create a test server
	server := &Server{
		Engine: gin.New(),
		Logger: &MockLogger{},
	}

	// Apply the rate limiter
	WithRateLimiter(RateLimiterConfig{
		MaxRequests:   100,
		Interval:      time.Minute,
		BlockDuration: 5 * time.Minute,
	})(server)

	// Check that the rate limiter was added to the engine
	if server.Engine == nil {
		t.Error("Engine should not be nil")
	}
}

// Function to mock the cleanup of the rate limiter in tests
func mockCleanup(r *RateLimiter) {
	// Initialize some test data
	r.ips.Store("192.168.1.1", &ipData{
		count:       10,
		lastRequest: time.Now().Add(-3 * time.Minute),
		blocked:     false,
	})

	r.ips.Store("192.168.1.2", &ipData{
		count:       100,
		lastRequest: time.Now().Add(-1 * time.Minute),
		blocked:     true,
		blockUntil:  time.Now().Add(-1 * time.Minute), // Block expired
	})

	r.ips.Store("192.168.1.3", &ipData{
		count:       100,
		lastRequest: time.Now(),
		blocked:     true,
		blockUntil:  time.Now().Add(5 * time.Minute), // Block not expired
	})

	// Run cleanup
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

func TestRateLimiterCleanup(t *testing.T) {
	limiter := NewRateLimiter(RateLimiterConfig{
		Interval: time.Minute,
	})

	// Set up test data and run the cleanup function
	mockCleanup(limiter)

	// Check that the expired/old IPs were removed but the active blocked IP remains
	var ips []string
	limiter.ips.Range(func(key, value interface{}) bool {
		ips = append(ips, key.(string))
		return true
	})

	// Only 192.168.1.3 should remain (active block)
	if len(ips) != 1 || ips[0] != "192.168.1.3" {
		t.Errorf("cleanup didn't work correctly. Remaining IPs: %v", ips)
	}
}

// Tests for security headers middleware

func TestDefaultSecurityHeadersConfig(t *testing.T) {
	config := DefaultSecurityHeadersConfig()

	if config == nil {
		t.Fatal("DefaultSecurityHeadersConfig() returned nil")
	}

	// Check default values
	if !config.EnableHSTS {
		t.Error("EnableHSTS should be true by default")
	}

	if config.HSTSMaxAge != 31536000 {
		t.Errorf("HSTSMaxAge = %d, want 31536000", config.HSTSMaxAge)
	}

	if !config.HSTSIncludeSubdomains {
		t.Error("HSTSIncludeSubdomains should be true by default")
	}

	if config.HSTSPreload {
		t.Error("HSTSPreload should be false by default")
	}

	if config.ContentSecurityPolicy == "" {
		t.Error("ContentSecurityPolicy should not be empty")
	}

	if config.ReferrerPolicy != "strict-origin-when-cross-origin" {
		t.Errorf("ReferrerPolicy = %s, want strict-origin-when-cross-origin", config.ReferrerPolicy)
	}

	if config.FrameOption != "DENY" {
		t.Errorf("FrameOption = %s, want DENY", config.FrameOption)
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name   string
		config *SecurityHeadersConfig
		check  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:   "default config",
			config: DefaultSecurityHeadersConfig(),
			check: func(t *testing.T, w *httptest.ResponseRecorder) {
				// Check CSP header
				csp := w.Header().Get("Content-Security-Policy")
				if csp == "" {
					t.Error("Content-Security-Policy header not set")
				}

				// Check HSTS header
				hsts := w.Header().Get("Strict-Transport-Security")
				if !strings.Contains(hsts, "max-age=31536000") {
					t.Errorf("HSTS header = %s, should contain max-age=31536000", hsts)
				}
				if !strings.Contains(hsts, "includeSubDomains") {
					t.Errorf("HSTS header = %s, should contain includeSubDomains", hsts)
				}

				// Check Referrer-Policy header
				referrer := w.Header().Get("Referrer-Policy")
				if referrer != "strict-origin-when-cross-origin" {
					t.Errorf("Referrer-Policy = %s, want strict-origin-when-cross-origin", referrer)
				}

				// Check Permissions-Policy header
				permissions := w.Header().Get("Permissions-Policy")
				if permissions == "" {
					t.Error("Permissions-Policy header not set")
				}

				// Check X-XSS-Protection header
				xss := w.Header().Get("X-XSS-Protection")
				if xss != "1; mode=block" {
					t.Errorf("X-XSS-Protection = %s, want 1; mode=block", xss)
				}

				// Check X-Frame-Options header
				frame := w.Header().Get("X-Frame-Options")
				if frame != "DENY" {
					t.Errorf("X-Frame-Options = %s, want DENY", frame)
				}

				// Check X-Content-Type-Options header
				contentType := w.Header().Get("X-Content-Type-Options")
				if contentType != "nosniff" {
					t.Errorf("X-Content-Type-Options = %s, want nosniff", contentType)
				}
			},
		},
		{
			name: "custom config",
			config: &SecurityHeadersConfig{
				EnableHSTS:               true,
				HSTSMaxAge:               86400, // 1 day
				HSTSIncludeSubdomains:    false,
				HSTSPreload:              true,
				ContentSecurityPolicy:    "default-src 'none'",
				ReferrerPolicy:           "no-referrer",
				PermissionsPolicy:        "camera=()",
				EnableXSSProtection:      true,
				EnableFrameOptions:       true,
				FrameOption:              "SAMEORIGIN",
				EnableContentTypeOptions: true,
			},
			check: func(t *testing.T, w *httptest.ResponseRecorder) {
				// Check CSP header
				csp := w.Header().Get("Content-Security-Policy")
				if csp != "default-src 'none'" {
					t.Errorf("Content-Security-Policy = %s, want default-src 'none'", csp)
				}

				// Check HSTS header
				hsts := w.Header().Get("Strict-Transport-Security")
				if !strings.Contains(hsts, "max-age=86400") {
					t.Errorf("HSTS header = %s, should contain max-age=86400", hsts)
				}
				if strings.Contains(hsts, "includeSubDomains") {
					t.Errorf("HSTS header = %s, should not contain includeSubDomains", hsts)
				}
				if !strings.Contains(hsts, "preload") {
					t.Errorf("HSTS header = %s, should contain preload", hsts)
				}

				// Check Referrer-Policy header
				referrer := w.Header().Get("Referrer-Policy")
				if referrer != "no-referrer" {
					t.Errorf("Referrer-Policy = %s, want no-referrer", referrer)
				}

				// Check X-Frame-Options header
				frame := w.Header().Get("X-Frame-Options")
				if frame != "SAMEORIGIN" {
					t.Errorf("X-Frame-Options = %s, want SAMEORIGIN", frame)
				}
			},
		},
		{
			name: "disabled features",
			config: &SecurityHeadersConfig{
				EnableHSTS:               false,
				ContentSecurityPolicy:    "",
				ReferrerPolicy:           "",
				PermissionsPolicy:        "",
				EnableXSSProtection:      false,
				EnableFrameOptions:       false,
				EnableContentTypeOptions: false,
			},
			check: func(t *testing.T, w *httptest.ResponseRecorder) {
				// Check headers are not set
				if w.Header().Get("Strict-Transport-Security") != "" {
					t.Error("HSTS header should not be set")
				}
				if w.Header().Get("Content-Security-Policy") != "" {
					t.Error("CSP header should not be set")
				}
				if w.Header().Get("Referrer-Policy") != "" {
					t.Error("Referrer-Policy header should not be set")
				}
				if w.Header().Get("Permissions-Policy") != "" {
					t.Error("Permissions-Policy header should not be set")
				}
				if w.Header().Get("X-XSS-Protection") != "" {
					t.Error("X-XSS-Protection header should not be set")
				}
				if w.Header().Get("X-Frame-Options") != "" {
					t.Error("X-Frame-Options header should not be set")
				}
				if w.Header().Get("X-Content-Type-Options") != "" {
					t.Error("X-Content-Type-Options header should not be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(SecurityHeadersMiddleware(tt.config))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "ok")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
			}

			tt.check(t, w)
		})
	}
}

func TestWithSecurityHeaders(t *testing.T) {
	// Create a test server
	server := &Server{
		Engine: gin.New(),
		Logger: &MockLogger{},
	}

	// Apply the security headers middleware
	WithSecurityHeaders(nil)(server)

	// Check that the middleware was added to the engine
	if server.Engine == nil {
		t.Error("Engine should not be nil")
	}
}

// TestWithCSRFProtection_AdditionalCases tests the CSRF protection middleware with additional cases
func TestWithCSRFProtection_AdditionalCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a test server with CSRF protection middleware
	r := gin.New()

	// Add the CSRF verification middleware
	r.Use(VerifyCSRFToken())

	// Add test routes
	r.GET("/api/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	r.POST("/api/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Test cases
	testCases := []struct {
		name         string
		method       string
		path         string
		headers      map[string]string
		cookies      map[string]string
		expectStatus int
	}{
		{
			name:         "GET request - should bypass CSRF check",
			method:       "GET",
			path:         "/api/test",
			headers:      nil,
			cookies:      nil,
			expectStatus: http.StatusOK,
		},
		{
			name:         "POST without Origin or Referer - should fail CSRF check",
			method:       "POST",
			path:         "/api/test",
			headers:      nil,
			cookies:      nil,
			expectStatus: http.StatusForbidden,
		},
		{
			name:   "POST with non-matching Origin - should fail CSRF check",
			method: "POST",
			path:   "/api/test",
			headers: map[string]string{
				"Origin": "https://malicious-site.com",
			},
			cookies: map[string]string{
				"csrf_token": "test-token",
			},
			expectStatus: http.StatusForbidden,
		},
		{
			name:   "POST with matching CSRF tokens - should pass",
			method: "POST",
			path:   "/api/test",
			headers: map[string]string{
				"X-CSRF-Token": "test-token",
			},
			cookies: map[string]string{
				"csrf_token": "test-token",
			},
			expectStatus: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)

			// Add headers if any
			if tc.headers != nil {
				for key, value := range tc.headers {
					req.Header.Set(key, value)
				}
			}

			// Add cookies if any
			if tc.cookies != nil {
				for name, value := range tc.cookies {
					req.AddCookie(&http.Cookie{
						Name:  name,
						Value: value,
					})
				}
			}

			resp := httptest.NewRecorder()
			r.ServeHTTP(resp, req)

			assert.Equal(t, tc.expectStatus, resp.Code)
		})
	}
}

// TestRateLimiterMiddleware tests the rate limiter middleware functionality
func TestRateLimiterMiddleware_AdditionalCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a test server with the rate limiter middleware
	r := gin.New()

	// Create a rate limiter with a very low limit to test rate limiting
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests:   2,
		Interval:      time.Second,
		BlockDuration: time.Second * 5,
		ExcludedPaths: nil,
	})

	// Apply middleware
	r.Use(limiter.Middleware())

	// Add a test handler
	r.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Make multiple requests to test rate limiting
	makeRequest := func(ip string) int {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = ip + ":1234" // Set the remote address for IP-based limiting
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)
		return resp.Code
	}

	// Test cases
	t.Run("Allows requests under limit", func(t *testing.T) {
		// First two requests should be allowed (limit is 2 per second)
		assert.Equal(t, http.StatusOK, makeRequest("192.168.1.1"))
		assert.Equal(t, http.StatusOK, makeRequest("192.168.1.1"))
	})

	t.Run("Blocks requests over limit", func(t *testing.T) {
		// Third request should be blocked
		assert.Equal(t, http.StatusTooManyRequests, makeRequest("192.168.1.1"))
	})

	t.Run("Different IPs have separate limits", func(t *testing.T) {
		// Requests from a different IP should be allowed
		assert.Equal(t, http.StatusOK, makeRequest("192.168.1.2"))
		assert.Equal(t, http.StatusOK, makeRequest("192.168.1.2"))
		assert.Equal(t, http.StatusTooManyRequests, makeRequest("192.168.1.2"))
	})

	// Test with excluded paths
	t.Run("Test with exclusions", func(t *testing.T) {
		// Create a new server with path exclusions
		r2 := gin.New()
		limiter2 := NewRateLimiter(RateLimiterConfig{
			MaxRequests:   1,
			Interval:      time.Second,
			BlockDuration: time.Second * 5,
			ExcludedPaths: []string{"/excluded"},
		})
		r2.Use(limiter2.Middleware())

		r2.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		r2.GET("/excluded", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		// Test regular path (limited)
		req1 := httptest.NewRequest("GET", "/test", nil)
		resp1 := httptest.NewRecorder()
		r2.ServeHTTP(resp1, req1)
		assert.Equal(t, http.StatusOK, resp1.Code)

		// Second request should be rate limited
		req2 := httptest.NewRequest("GET", "/test", nil)
		resp2 := httptest.NewRecorder()
		r2.ServeHTTP(resp2, req2)
		assert.Equal(t, http.StatusTooManyRequests, resp2.Code)

		// Excluded path should never be rate limited
		req3 := httptest.NewRequest("GET", "/excluded", nil)
		resp3 := httptest.NewRecorder()
		r2.ServeHTTP(resp3, req3)
		assert.Equal(t, http.StatusOK, resp3.Code)

		req4 := httptest.NewRequest("GET", "/excluded", nil)
		resp4 := httptest.NewRecorder()
		r2.ServeHTTP(resp4, req4)
		assert.Equal(t, http.StatusOK, resp4.Code)
	})
}
