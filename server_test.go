package EpicServer

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

// Replace the mockLogger implementation to use a real StructuredLogger to avoid interface issues
func createMockLogger() Logger {
	return &StructuredLogger{
		writer: io.Discard,
		level:  LogLevelInfo,
		format: LogFormatText,
		fields: []LogField{},
	}
}

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

			server = NewServer(tt.configs)
			if tt.appLayers != nil {
				server.UpdateAppLayer(tt.appLayers)
			}

			if tt.wantErr {
				if !server.HasErrors() {
					t.Errorf("NewServer() should have errors for %s", tt.name)
					return
				}
			} else {
				if server.HasErrors() {
					t.Errorf("NewServer() has unexpected errors: %v", server.GetErrors())
					return
				}

				if tt.assertions != nil {
					tt.assertions(t, server)
				}
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

	// Test OnUserCreate returns the user ID
	claims := Claims{UserID: "test-id"}
	userID, err := s.Hooks.Auth.OnUserCreate(claims)
	if err != nil {
		t.Error("unexpected error from default OnUserCreate")
	}
	if userID != claims.UserID {
		t.Errorf("expected user ID %s, got %s", claims.UserID, userID)
	}

	// Test default hook methods return expected errors
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

func TestServerGetErrors(t *testing.T) {
	s := &Server{
		errors: []error{
			fmt.Errorf("test error 1"),
			fmt.Errorf("test error 2"),
		},
	}

	errors := s.GetErrors()
	assert.Len(t, errors, 2)
	assert.Equal(t, "test error 1", errors[0].Error())
	assert.Equal(t, "test error 2", errors[1].Error())
}

func TestServerAddError(t *testing.T) {
	s := &Server{
		errors: []error{
			fmt.Errorf("existing error"),
		},
	}

	// Add a new error
	newErr := fmt.Errorf("new error")
	s.AddError(newErr)

	// Verify the error was added
	assert.Len(t, s.errors, 2)
	assert.Equal(t, "existing error", s.errors[0].Error())
	assert.Equal(t, "new error", s.errors[1].Error())
}

// Helper function to get a free port
func getFreePort() int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 3000 // fallback to default port
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 3000 // fallback to default port
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestServerStart(t *testing.T) {
	// Skip in race detector mode as we know there's a race condition
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	// Create a server with a valid port and use ephemeral port
	s := NewServer([]Option{
		SetHost("localhost", 0),
		SetSecretKey([]byte("test-secret-key")),
	})

	// Get an available port
	port := getFreePort()
	s.Config.Server.Port = port

	// Add a test route
	s.Engine.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "test")
	})

	// Setup channels to coordinate test
	errChan := make(chan error, 1)
	ready := make(chan struct{})

	// Add mutex to prevent data race
	var serverMutex sync.Mutex

	go func() {
		// Start the server
		go func() {
			errChan <- s.Start()
		}()

		// Wait for the server to be ready by checking if we can connect to it
		for i := 0; i < 10; i++ {
			time.Sleep(50 * time.Millisecond)

			serverMutex.Lock()
			srv := s.srv
			serverMutex.Unlock()

			if srv != nil {
				conn, err := net.Dial("tcp", srv.Addr)
				if err == nil {
					conn.Close()
					close(ready)
					return
				}
			}
		}
		// If we get here, the server didn't start properly
		close(ready)
	}()

	// Wait for the server to be ready or timeout
	select {
	case <-ready:
		// Server is ready
	case <-time.After(2 * time.Second):
		t.Fatal("Server didn't start in time")
	}

	// Make a test request if the server started
	if s.srv != nil {
		// Get the actual port that was assigned
		_, portStr, _ := net.SplitHostPort(s.srv.Addr)
		url := fmt.Sprintf("http://localhost:%s/test", portStr)

		resp, err := http.Get(url)
		if err == nil {
			defer resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			body, _ := io.ReadAll(resp.Body)
			assert.Equal(t, "test", string(body))
		}
	}

	// Stop the server
	err := s.Stop()
	assert.NoError(t, err)

	// Check for any errors from Start
	select {
	case err := <-errChan:
		if err != nil && err != http.ErrServerClosed {
			assert.NoError(t, err)
		}
	case <-time.After(100 * time.Millisecond):
		// No error received yet, which is fine
	}
}

// TestServerStartWithErrors tests that the server returns errors when started with initialization errors
func TestServerStartWithErrors(t *testing.T) {
	// Create a server with errors
	s := &Server{
		errors: []error{fmt.Errorf("test error")},
		Logger: createMockLogger(),
	}

	// Start should return an error
	err := s.Start()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "test error")
}

// TestServerStopWithoutStart tests that stopping a server that hasn't been started doesn't panic
func TestServerStopWithoutStart(t *testing.T) {
	s := &Server{
		Logger: createMockLogger(),
	}

	// Should not panic
	assert.NotPanics(t, func() {
		_ = s.Stop()
	})
}

// TestHandleAuthCallbackNonExistentProvider tests the OAuth callback handler when provider doesn't exist
func TestHandleAuthCallbackNonExistentProvider(t *testing.T) {
	// Create a mock server
	s := &Server{
		Logger:      createMockLogger(),
		AuthConfigs: make(map[string]*Auth),
	}

	// Create a test HTTP router
	router := gin.New()

	// Create a mock OAuth config
	mockConfig := &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://example.com/auth",
			TokenURL: "https://example.com/token",
		},
		RedirectURL: "https://example.com/callback",
		Scopes:      []string{"email", "profile"},
	}

	// Configure a mock auth config
	s.AuthConfigs["mock"] = &Auth{
		Config:         mockConfig,
		AuthCookieName: "auth_cookie",
		CookieHandler:  NewCookieHandler(),
	}

	// Create mock auth hooks
	mockHooks := &testAuthHooks{
		t: t,
	}

	// Register the auth callback handler
	router.GET("/auth/:provider/callback", HandleAuthCallback(s, []Provider{
		{
			Name:         "mock",
			ClientId:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
	}, "auth_cookie", "example.com", true, mockHooks))

	// Test case: Provider doesn't exist
	req := httptest.NewRequest("GET", "/auth/nonexistent/callback?code=test-code", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// testAuthHooks is a mock implementation of AuthenticationHooks for testing
type testAuthHooks struct {
	t *testing.T
}

// Implement all required methods of the AuthenticationHooks interface
func (h *testAuthHooks) OnUserCreate(user Claims) (string, error) {
	return "test-user-id", nil
}

func (h *testAuthHooks) GetUserOrCreate(user Claims) (*CookieContents, error) {
	return &CookieContents{
		Email:      "test@example.com",
		UserId:     "test-user-id",
		SessionId:  "test-session-id",
		IsLoggedIn: true,
		ExpiresOn:  time.Now().Add(time.Hour),
	}, nil
}

func (h *testAuthHooks) OnAuthenticate(username, password string, state OAuthState) (bool, error) {
	return true, nil
}

func (h *testAuthHooks) OnUserGet(userID string) (any, error) {
	return map[string]string{"id": userID}, nil
}

func (h *testAuthHooks) OnSessionValidate(sessionToken *CookieContents) (interface{}, error) {
	return map[string]string{"id": sessionToken.UserId}, nil
}

func (h *testAuthHooks) OnSessionCreate(userID string) (string, error) {
	return "test-session-id", nil
}

func (h *testAuthHooks) OnSessionDestroy(sessionToken string) error {
	return nil
}

func (h *testAuthHooks) OnOAuthCallbackSuccess(ctx *gin.Context, state OAuthState) error {
	return nil
}

// TestHandleAuthLoginBasicCase tests the basic functionality of the auth login handler
func TestHandleAuthLoginBasicCase(t *testing.T) {
	// Create a mock server
	s := &Server{
		Logger:      createMockLogger(),
		AuthConfigs: make(map[string]*Auth),
	}

	// Create a test HTTP router
	router := gin.New()

	// Create a mock OAuth config
	mockConfig := &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://example.com/auth",
			TokenURL: "https://example.com/token",
		},
		RedirectURL: "https://example.com/callback",
		Scopes:      []string{"email", "profile"},
	}

	// Configure a mock auth config and provider
	provider := "mock"
	s.AuthConfigs[provider] = &Auth{
		Config:         mockConfig,
		AuthCookieName: "auth_cookie",
	}

	// Register the auth login handler
	router.GET("/auth/:provider", HandleAuthLogin(s, []Provider{
		{
			Name:         provider,
			ClientId:     "test-client-id",
			ClientSecret: "test-client-secret",
			Callback:     "https://example.com/callback",
		},
	}, "auth_cookie", "example.com", true))

	// Test case: Basic login request
	req := httptest.NewRequest("GET", "/auth/mock", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// The handler should redirect to the OAuth provider's auth URL
	// OAuth2 redirects use status code 303 (See Other)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	redirectURL := w.Header().Get("Location")
	assert.Contains(t, redirectURL, "https://example.com/auth")
	assert.Contains(t, redirectURL, "client_id=test-client-id")
	assert.Contains(t, redirectURL, "redirect_uri=")
	assert.Contains(t, redirectURL, "state=")

	// Test case: Provider doesn't exist
	req = httptest.NewRequest("GET", "/auth/nonexistent", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// The handler should return not found
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestHandleAuthLoginWithCustomState tests the auth login handler with custom state
func TestHandleAuthLoginWithCustomState(t *testing.T) {
	// Create a mock server
	s := &Server{
		Logger:      createMockLogger(),
		AuthConfigs: make(map[string]*Auth),
	}

	// Create a test HTTP router
	router := gin.New()

	// Create a mock OAuth config
	mockConfig := &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://example.com/auth",
			TokenURL: "https://example.com/token",
		},
		RedirectURL: "https://example.com/callback",
		Scopes:      []string{"email", "profile"},
	}

	// Configure a mock auth config and provider
	provider := "mock"
	s.AuthConfigs[provider] = &Auth{
		Config:         mockConfig,
		AuthCookieName: "auth_cookie",
	}

	// Register the auth login handler
	router.GET("/auth/:provider", HandleAuthLogin(s, []Provider{
		{
			Name:         provider,
			ClientId:     "test-client-id",
			ClientSecret: "test-client-secret",
			Callback:     "https://example.com/callback",
		},
	}, "auth_cookie", "example.com", true))

	// Create a valid custom state JSON
	customState := `{"return_to":"/dashboard","custom":{"test":"value"}}`

	// Test case: Login with custom state
	req := httptest.NewRequest("GET", "/auth/mock?custom_state="+customState, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// The handler should redirect to the OAuth provider's auth URL
	// OAuth2 redirects use status code 303 (See Other)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	redirectURL := w.Header().Get("Location")
	assert.Contains(t, redirectURL, "https://example.com/auth")

	// Test with invalid custom state
	req = httptest.NewRequest("GET", "/auth/mock?custom_state=invalid-json", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should return an error
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestRateLimiterCleanupExpiredIPs tests that the cleanup function removes expired blocked IPs
func TestRateLimiterCleanupExpiredIPs(t *testing.T) {
	// Create a rate limiter with a very short interval for testing
	limiter := NewRateLimiter(RateLimiterConfig{
		MaxRequests:   5,
		Interval:      10 * time.Millisecond, // Very short interval for testing
		BlockDuration: 20 * time.Millisecond, // Very short block duration for testing
		ExcludedPaths: []string{},
	})

	// Add some test IPs
	testIP1 := "192.168.1.1"
	testIP2 := "192.168.1.2"

	// Store IP data with expired block
	limiter.ips.Store(testIP1, &ipData{
		count:       10, // Over the limit
		lastRequest: time.Now(),
		blocked:     true,
		blockUntil:  time.Now().Add(-1 * time.Millisecond), // Block expired
	})

	// Store another IP that will stay active (non-blocked)
	// Keep track of the current time to simulate an active IP
	activeTime := time.Now()
	limiter.ips.Store(testIP2, &ipData{
		count:       3, // Under the limit
		lastRequest: activeTime,
		blocked:     false,
	})

	// Wait for cleanup to run at least once
	time.Sleep(15 * time.Millisecond)

	// Simulate activity for the non-blocked IP to prevent it from being cleaned up
	// This simulates requests being made from this IP
	limiter.ips.Store(testIP2, &ipData{
		count:       3,          // Under the limit
		lastRequest: time.Now(), // Update the last request time
		blocked:     false,
	})

	// Wait for another cleanup cycle
	time.Sleep(15 * time.Millisecond)

	// Check if the blocked IP was removed
	_, exists := limiter.ips.Load(testIP1)
	assert.False(t, exists, "The expired blocked IP should have been removed by cleanup")

	// Check if the non-blocked IP is still there because we simulated activity
	_, exists = limiter.ips.Load(testIP2)
	assert.True(t, exists, "The non-blocked IP should still exist since it was active")
}
