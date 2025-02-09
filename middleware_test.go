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

	tests := []struct {
		name         string
		method       string
		setupRequest func(*http.Request, string) // Changed to take request and token
		wantCode     int
	}{
		{
			name:         "GET request bypasses CSRF",
			method:       "GET",
			setupRequest: nil,
			wantCode:     http.StatusOK,
		},
		{
			name:         "HEAD request bypasses CSRF",
			method:       "HEAD",
			setupRequest: nil,
			wantCode:     http.StatusOK,
		},
		{
			name:   "valid token",
			method: "POST",
			setupRequest: func(req *http.Request, token string) {
				req.Header.Set("X-CSRF-Token", token)
				req.AddCookie(&http.Cookie{
					Name:     "csrf_token",
					Value:    token,
					Path:     "/",
					Domain:   "localhost",
					Secure:   false,
					HttpOnly: true,
				})
			},
			wantCode: http.StatusOK,
		},
		{
			name:   "invalid token",
			method: "POST",
			setupRequest: func(req *http.Request, token string) {
				req.Header.Set("X-CSRF-Token", "invalid")
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
		{
			name:   "missing header token",
			method: "POST",
			setupRequest: func(req *http.Request, token string) {
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
		{
			name:   "missing cookie",
			method: "POST",
			setupRequest: func(req *http.Request, token string) {
				req.Header.Set("X-CSRF-Token", token)
			},
			wantCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(VerifyCSRFToken())

			router.Any("/test", func(c *gin.Context) {
				if c.Request.Method == "HEAD" {
					c.Status(http.StatusOK)
					return
				}
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

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(3, 1, 200*time.Millisecond)

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
	rl := NewRateLimiter(10, 1, 100*time.Millisecond)
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
	rl := NewRateLimiter(2, 1, 200*time.Millisecond)

	r := gin.New()
	r.Use(RateLimiterMiddleware(rl))
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

// MockLogger is a mock implementation of the Logger interface.
type MockLogger struct {
	Messages []string
}

func (m *MockLogger) Info(args ...interface{}) {
	m.Messages = append(m.Messages, fmt.Sprint(args...))
}

func (m *MockLogger) Debug(args ...interface{}) {
	m.Messages = append(m.Messages, fmt.Sprint(args...))
}

func (m *MockLogger) Error(args ...interface{}) {
	m.Messages = append(m.Messages, fmt.Sprint(args...))
}

func (m *MockLogger) Warn(args ...interface{}) {
	m.Messages = append(m.Messages, fmt.Sprint(args...))
}

func TestRequestTimingMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockLogger := &MockLogger{}

	r := gin.New()
	r.Use(RequestTimingMiddleware(mockLogger))
	r.GET("/test", func(c *gin.Context) {
		time.Sleep(50 * time.Millisecond) // Simulate some processing time
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if len(mockLogger.Messages) == 0 {
		t.Fatal("expected log message, got none")
	}

	expectedPrefix := "Request GET /test took"
	if !strings.HasPrefix(mockLogger.Messages[0], expectedPrefix) {
		t.Errorf("log message = %q, want prefix %q", mockLogger.Messages[0], expectedPrefix)
	}
}
