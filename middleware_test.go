package EpicServer

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
