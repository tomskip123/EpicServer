package EpicServer

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewServer(t *testing.T) {
	tests := []struct {
		name       string
		configs    []Option
		appLayers  []AppLayer
		wantErr    bool
		assertions func(*testing.T, *Server)
	}{
		{
			name: "valid default configuration",
			configs: []Option{
				SetSecretKey([]byte("test-secret-key")),
			},
			assertions: func(t *testing.T, s *Server) {
				if s.Config.Server.Host != "localhost" {
					t.Errorf("expected host localhost, got %s", s.Config.Server.Host)
				}
				if s.Config.Server.Port != 3000 {
					t.Errorf("expected port 3000, got %d", s.Config.Server.Port)
				}
				if s.Engine == nil {
					t.Error("expected engine to be initialized")
				}
				if s.Logger == nil {
					t.Error("expected logger to be initialized")
				}
			},
		},
		{
			name: "custom host and port",
			configs: []Option{
				SetHost("127.0.0.1", 8080),
				SetSecretKey([]byte("test-secret-key")),
			},
			assertions: func(t *testing.T, s *Server) {
				if s.Config.Server.Host != "127.0.0.1" {
					t.Errorf("expected host 127.0.0.1, got %s", s.Config.Server.Host)
				}
				if s.Config.Server.Port != 8080 {
					t.Errorf("expected port 8080, got %d", s.Config.Server.Port)
				}
			},
		},
		{
			name: "missing secret key",
			configs: []Option{
				SetHost("localhost", 8080),
			},
			wantErr: true,
		},
		{
			name: "with custom config",
			configs: []Option{
				SetSecretKey([]byte("test-secret-key")),
				SetCustomConfig(map[string]interface{}{
					"test": "value",
				}),
			},
			assertions: func(t *testing.T, s *Server) {
				custom := GetCustomConfig(s).(map[string]interface{})
				if custom["test"] != "value" {
					t.Error("custom config not set correctly")
				}
			},
		},
		{
			name: "with multiple app layers",
			configs: []Option{
				SetSecretKey([]byte("test-secret-key")),
			},
			appLayers: []AppLayer{
				WithHealthCheck("/health"),
				WithCompression(),
				WithEnvironment("test"),
			},
			assertions: func(t *testing.T, s *Server) {
				// Test health endpoint
				w := httptest.NewRecorder()
				req := httptest.NewRequest("GET", "/health", nil)
				s.Engine.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					t.Errorf("health check failed: got %d, want %d", w.Code, http.StatusOK)
				}

				// Verify environment
				if gin.Mode() != gin.TestMode {
					t.Errorf("expected test mode, got %s", gin.Mode())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *Server
			panicked := false

			func() {
				defer func() {
					if r := recover(); r != nil {
						panicked = true
					}
				}()
				server = NewServer(tt.configs)
				if tt.appLayers != nil {
					server.UpdateAppLayer(tt.appLayers)
				}
			}()

			if panicked != tt.wantErr {
				t.Errorf("NewServer() panic = %v, wantErr %v", panicked, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.assertions != nil {
				tt.assertions(t, server)
			}
		})
	}
}

func TestAppLayers(t *testing.T) {
	tests := []struct {
		name       string
		appLayers  []AppLayer
		testPath   string
		wantStatus int
		wantHeader string
		wantValue  string
	}{
		{
			name: "health check layer",
			appLayers: []AppLayer{
				WithHealthCheck("/health"),
			},
			testPath:   "/health",
			wantStatus: http.StatusOK,
		},
		{
			name: "compression layer",
			appLayers: []AppLayer{
				WithCompression(),
			},
			testPath:   "/test",
			wantStatus: http.StatusOK,
			wantHeader: "Content-Encoding",
			wantValue:  "gzip",
		},
		{
			name: "cors layer",
			appLayers: []AppLayer{
				WithCors([]string{"http://example.com"}),
			},
			testPath:   "/test",
			wantStatus: http.StatusOK,
			wantHeader: "Access-Control-Allow-Origin",
			wantValue:  "http://example.com",
		},
		{
			name: "www redirect layer",
			appLayers: []AppLayer{
				WithRemoveWWW(),
			},
			testPath:   "/test",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})
			s.UpdateAppLayer(tt.appLayers)

			// Add test endpoint if not health check
			if !strings.Contains(tt.testPath, "health") {
				s.Engine.GET(tt.testPath, func(c *gin.Context) {
					c.String(http.StatusOK, "test")
				})
			}

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tt.testPath, nil)
			if tt.wantHeader == "Access-Control-Allow-Origin" {
				req.Header.Set("Origin", "http://example.com")
			} else if tt.wantHeader == "Content-Encoding" {
				req.Header.Set("Accept-Encoding", "gzip")
			}

			s.Engine.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, w.Code)
			}

			if tt.wantHeader != "" {
				if got := w.Header().Get(tt.wantHeader); got != tt.wantValue {
					t.Errorf("expected header %s=%s, got %s", tt.wantHeader, tt.wantValue, got)
				}
			}
		})
	}
}

func TestUpdateAppLayer(t *testing.T) {
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})

	called := false
	s.UpdateAppLayer([]AppLayer{
		func(s *Server) {
			called = true
		},
	})

	if !called {
		t.Error("UpdateAppLayer did not execute the layer")
	}
}

func TestEnvironmentSettings(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		wantMode    string
	}{
		{
			name:        "development mode",
			environment: "development",
			wantMode:    gin.DebugMode,
		},
		{
			name:        "production mode",
			environment: "production",
			wantMode:    gin.ReleaseMode,
		},
		{
			name:        "test mode",
			environment: "test",
			wantMode:    gin.TestMode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})
			s.UpdateAppLayer([]AppLayer{
				WithEnvironment(tt.environment),
			})

			if gin.Mode() != tt.wantMode {
				t.Errorf("expected mode %s, got %s", tt.wantMode, gin.Mode())
			}
		})
	}
}

func TestTrustedProxies(t *testing.T) {
	proxies := []string{"127.0.0.1", "10.0.0.0/8"}
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})
	s.UpdateAppLayer([]AppLayer{
		WithTrustedProxies(proxies),
	})

	// Test proxy configuration indirectly: since Gin's trusted proxies
	// settings are internal, we run a request to verify default route 404.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	s.Engine.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

func TestDefaultHooks(t *testing.T) {
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})

	if s.Hooks.Auth == nil {
		t.Error("default auth hooks not initialized")
	}

	// Test default hook methods return expected errors
	if _, err := s.Hooks.Auth.OnUserCreate(Claims{}); err == nil {
		t.Error("expected error from default OnUserCreate")
	}

	if _, err := s.Hooks.Auth.OnUserGet("test"); err == nil {
		t.Error("expected error from default OnUserGet")
	}
}

// func TestServer_Start(t *testing.T) {
// 	tests := []struct {
// 		name    string
// 		host    string
// 		port    int
// 		wantErr bool
// 	}{
// 		{
// 			name:    "valid port",
// 			host:    "localhost",
// 			port:    8000,
// 			wantErr: false,
// 		},
// 		{
// 			name:    "invalid port",
// 			host:    "localhost",
// 			port:    -1,
// 			wantErr: true,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if !tt.wantErr && !isPortAvailable(tt.host, tt.port) {
// 				t.Skip("Port not available")
// 			}

// 			s := NewServer([]Option{
// 				SetSecretKey([]byte("test-secret")),
// 				SetHost(tt.host, tt.port),
// 			})

// 			// Create a channel to signal when the server has started
// 			done := make(chan struct{})

// 			// Start the server in a separate goroutine
// 			go func() {
// 				defer close(done) // Signal that the server has started
// 				if err := s.Start(); err != nil {
// 					t.Errorf("failed to start server: %v", err)
// 				}
// 			}()

// 			// Allow some time for the server to start
// 			select {
// 			case <-done:
// 				// Server started successfully
// 			case <-time.After(5 * time.Second):
// 				t.Fatal("server did not start in time")
// 			}

// 			// Stop the server
// 			err := s.Stop()
// 			if err != nil {
// 				t.Errorf("failed to stop server: %v", err)
// 			}
// 		})
// 	}
// }

func isPortAvailable(host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

func TestServer_WithHttp2(t *testing.T) {
	s := NewServer([]Option{SetSecretKey([]byte("test-secret"))})
	s.UpdateAppLayer([]AppLayer{
		WithHttp2(),
	})

	if !s.Engine.UseH2C {
		t.Error("HTTP/2 not enabled")
	}
}

func TestServer_Initialization(t *testing.T) {
	tests := []struct {
		name       string
		configs    []Option
		appLayers  []AppLayer
		wantErr    bool
		assertions func(*testing.T, *Server)
	}{
		{
			name: "with custom logger",
			configs: []Option{
				SetSecretKey([]byte("test-secret")),
			},
			assertions: func(t *testing.T, s *Server) {
				if s.Logger == nil {
					t.Error("Logger not initialized")
				}
			},
		},
		{
			name: "with database initialization",
			configs: []Option{
				SetSecretKey([]byte("test-secret")),
			},
			assertions: func(t *testing.T, s *Server) {
				if s.Db == nil {
					t.Error("Database map not initialized")
				}
				if len(s.Db) != 0 {
					t.Error("Database map should be empty initially")
				}
			},
		},
		{
			name: "with cache initialization",
			configs: []Option{
				SetSecretKey([]byte("test-secret")),
			},
			assertions: func(t *testing.T, s *Server) {
				if s.Cache == nil {
					t.Error("Cache map not initialized")
				}
				if len(s.Cache) != 0 {
					t.Error("Cache map should be empty initially")
				}
			},
		},
		{
			name: "with hooks initialization",
			configs: []Option{
				SetSecretKey([]byte("test-secret")),
			},
			assertions: func(t *testing.T, s *Server) {
				if s.Hooks.Auth == nil {
					t.Error("Auth hooks not initialized")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s *Server
			defer func() {
				if r := recover(); (r != nil) != tt.wantErr {
					t.Errorf("NewServer() panic = %v, wantErr %v", r, tt.wantErr)
				}
			}()

			s = NewServer(tt.configs)
			if tt.appLayers != nil {
				s.UpdateAppLayer(tt.appLayers)
			}

			if !tt.wantErr && tt.assertions != nil {
				tt.assertions(t, s)
			}
		})
	}
}

func TestServer_DefaultConfig(t *testing.T) {
	config := defaultConfig()

	if config.Server.Host != "localhost" {
		t.Errorf("expected default host localhost, got %s", config.Server.Host)
	}

	if config.Server.Port != 3000 {
		t.Errorf("expected default port 3000, got %d", config.Server.Port)
	}
}

func TestServer_UpdateAppLayerOrder(t *testing.T) {
	executionOrder := []string{}
	s := NewServer([]Option{SetSecretKey([]byte("test-secret"))})

	// Add layers in specific order
	s.UpdateAppLayer([]AppLayer{
		func(s *Server) { executionOrder = append(executionOrder, "first") },
		func(s *Server) { executionOrder = append(executionOrder, "second") },
		func(s *Server) { executionOrder = append(executionOrder, "third") },
	})

	// Verify execution order
	expected := []string{"first", "second", "third"}
	for i, v := range executionOrder {
		if v != expected[i] {
			t.Errorf("layer execution order incorrect, got %v want %v", executionOrder, expected)
		}
	}
}

func TestServer_MultipleLayerUpdates(t *testing.T) {
	count := 0
	s := NewServer([]Option{SetSecretKey([]byte("test-secret"))})

	// Add layers multiple times
	updates := [][]AppLayer{
		{func(s *Server) { count++ }},
		{func(s *Server) { count++ }},
		{func(s *Server) { count++ }},
	}

	for _, update := range updates {
		s.UpdateAppLayer(update)
	}

	if count != 3 {
		t.Errorf("expected 3 layer executions, got %d", count)
	}
}

// New test: calling Stop without having started the server should be safe.
func TestServer_StopWithoutStart(t *testing.T) {
	s := NewServer([]Option{SetSecretKey([]byte("test-secret"))})
	if err := s.Stop(); err != nil {
		t.Errorf("Stop() returned error on a non-started server: %v", err)
	}
}

// New test: WithRemoveWWW redirect behavior.
// This assumes that the WithRemoveWWW middleware triggers a redirect when the host starts with "www.".
func TestRemoveWWWRedirectBehavior(t *testing.T) {
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})
	s.UpdateAppLayer([]AppLayer{
		WithRemoveWWW(),
	})

	// Dummy handler for test route.
	s.Engine.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "hello")
	})

	// Simulate request from a host using "www."
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://www.example.com/test", nil)
	s.Engine.ServeHTTP(w, req)

	// Depending on your middleware implementation, expect a redirect.
	// Here we check for a 301 or 302 status and a non-empty Location header.
	if w.Code != http.StatusMovedPermanently && w.Code != http.StatusFound {
		t.Errorf("expected redirect status (301 or 302), got %d", w.Code)
	}
	if location := w.Header().Get("Location"); location == "" {
		t.Error("expected Location header to be set for www redirect")
	}
}
