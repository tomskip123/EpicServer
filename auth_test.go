package EpicServer

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// Update the setSecureCookieKeys function to use proper Base64 encoded 32-byte keys
func setSecureCookieKeys() {
	// Generate 32-byte keys and encode to Base64
	hashKey := make([]byte, 32)
	blockKey := make([]byte, 32)

	// Fill with test values
	for i := 0; i < 32; i++ {
		hashKey[i] = byte(i)
		blockKey[i] = byte(i)
	}

	os.Setenv("SECURE_COOKIE_HASH_KEY", base64.StdEncoding.EncodeToString(hashKey))
	os.Setenv("SECURE_COOKIE_BLOCK_KEY", base64.StdEncoding.EncodeToString(blockKey))
}

// TestMain ensures secure cookie keys are set before each test runs.
func TestMain(m *testing.M) {
	setSecureCookieKeys()
	code := m.Run()
	os.Unsetenv("SECURE_COOKIE_HASH_KEY")
	os.Unsetenv("SECURE_COOKIE_BLOCK_KEY")
	os.Exit(code)
}

func TestWithAuth(t *testing.T) {
	// Setup
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})

	setSecureCookieKeys() // Ensure keys are set before test

	providers := []Provider{
		{
			Name:         "test",
			ClientId:     "test-client-id",
			ClientSecret: "test-client-secret",
			Callback:     "http://localhost:3000/auth/test/callback",
		},
	}

	sessionConfig := &SessionConfig{
		CookieName:      "test-cookie",
		CookieDomain:    "localhost",
		CookieSecure:    false,
		SessionDuration: time.Hour,
	}

	// Apply WithAuth app layer
	s.UpdateAppLayer([]AppLayer{WithAuth(providers, sessionConfig)})

	// Mock gin context with provider parameter
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/auth/test", nil)
	c.Request = req
	c.Params = []gin.Param{{Key: "provider", Value: "test"}}

	// Assert that AuthConfigs are created
	authConfig, exists := s.AuthConfigs["test"]
	if !exists {
		t.Error("AuthConfig not created for provider 'test'")
	}

	assert.NotNil(t, authConfig)
	assert.Equal(t, sessionConfig.CookieName, authConfig.AuthCookieName)

	// Test invalid provider config
	assert.Panics(t, func() {
		invalidProviders := []Provider{
			{
				Name: "test",
			},
		}

		s.UpdateAppLayer([]AppLayer{WithAuth(invalidProviders, sessionConfig)})
	}, "should panic due to invalid provider config")
}

func TestRegisterAuthRoutes(t *testing.T) {
	// Setup
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})
	providers := []Provider{
		{
			Name:         "test",
			ClientId:     "test-client-id",
			ClientSecret: "test-client-secret",
			Callback:     "http://localhost:3000/auth/test/callback",
		},
	}
	cookieName := "test-cookie"
	domain := "localhost"
	secure := false

	// Register auth routes
	RegisterAuthRoutes(s, providers, cookieName, domain, secure)

	// Check if routes are registered (indirectly by checking handler existence)
	routes := s.Engine.Routes()
	var loginRouteRegistered, callbackRouteRegistered, logoutRouteRegistered bool
	for _, route := range routes {
		if route.Path == "/auth/:provider" && route.Method == "GET" {
			loginRouteRegistered = true
		}
		if route.Path == "/auth/:provider/callback" && route.Method == "GET" {
			callbackRouteRegistered = true
		}
		if route.Path == "/auth/logout" && route.Method == "GET" {
			logoutRouteRegistered = true
		}
	}

	if !loginRouteRegistered {
		t.Error("Login route not registered")
	}
	if !callbackRouteRegistered {
		t.Error("Callback route not registered")
	}
	if !logoutRouteRegistered {
		t.Error("Logout route not registered")
	}
}

func TestWithAuthMiddleware(t *testing.T) {
	// Setup
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})
	sessionConfig := SessionConfig{
		CookieName: "test-cookie",
	}

	// Apply middleware
	s.UpdateAppLayer([]AppLayer{WithAuthMiddleware(sessionConfig)})

	// Define a test route that requires authentication
	s.Engine.GET("/protected", func(c *gin.Context) {
		session, _ := GetSession(c)
		c.String(http.StatusOK, fmt.Sprintf("Hello, %v", session.Email))
	})

	// Test case 1: No cookie provided
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/protected", nil)
	s.Engine.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Test case 2: Invalid cookie
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "test-cookie", Value: "invalid"})
	s.Engine.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetSessionFromCookie(t *testing.T) {
	// Setup
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})

	providers := []Provider{
		{
			Name:         "test",
			ClientId:     "test-client-id",
			ClientSecret: "test-client-secret",
			Callback:     "http://localhost:3000/auth/test/callback",
		},
	}

	sessionConfig := &SessionConfig{
		CookieName:      "test-cookie",
		CookieDomain:    "localhost",
		CookieSecure:    false,
		SessionDuration: time.Hour,
	}

	// Apply WithAuth app layer
	s.UpdateAppLayer([]AppLayer{WithAuth(providers, sessionConfig)})

	// Mock gin context and request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/test", nil)
	c.Request = req

	// Test case 1: No provider cookie
	_, err := GetSessionFromCookie(s, c, "test-cookie")
	assert.Error(t, err)

	// Test case 2: No session cookie
	c.Request.AddCookie(&http.Cookie{Name: "provider", Value: "test"})
	_, err = GetSessionFromCookie(s, c, "test-cookie")
	assert.Error(t, err)
}

func TestDefaultAuthHooks_GetUserOrCreate(t *testing.T) {
	hooks := &DefaultAuthHooks{}
	claims := Claims{
		Email:  "test@example.com",
		UserID: "123",
	}

	contents, err := hooks.GetUserOrCreate(claims)
	assert.NoError(t, err)
	assert.Equal(t, claims.Email, contents.Email)
	assert.Equal(t, claims.UserID, contents.UserId)
	assert.NotEmpty(t, contents.SessionId)
	assert.True(t, contents.IsLoggedIn)
	assert.WithinDuration(t, time.Now().Add(time.Hour), contents.ExpiresOn, time.Minute)
}

func TestDefaultAuthHooks_OnUserCreate(t *testing.T) {
	hooks := &DefaultAuthHooks{}
	claims := Claims{}

	_, err := hooks.OnUserCreate(claims)
	assert.Error(t, err)
	assert.EqualError(t, err, "user creation hook not implemented")
}

func TestDefaultAuthHooks_OnAuthenticate(t *testing.T) {
	hooks := &DefaultAuthHooks{}
	_, err := hooks.OnAuthenticate("user", "pass", OAuthState{})
	assert.Error(t, err)
	assert.EqualError(t, err, "on authenticate hook not implemented")
}

func TestDefaultAuthHooks_OnUserGet(t *testing.T) {
	hooks := &DefaultAuthHooks{}
	_, err := hooks.OnUserGet("123")
	assert.Error(t, err)
	assert.EqualError(t, err, "on user get hook not implemented")
}

func TestDefaultAuthHooks_OnSessionValidate(t *testing.T) {
	hooks := &DefaultAuthHooks{}
	_, err := hooks.OnSessionValidate(&CookieContents{})
	assert.Error(t, err)
	assert.EqualError(t, err, "on session validate hook not implemented")
}

func TestDefaultAuthHooks_OnSessionCreate(t *testing.T) {
	hooks := &DefaultAuthHooks{}
	_, err := hooks.OnSessionCreate("123")
	assert.Error(t, err)
	assert.EqualError(t, err, "on session create hook not implemented")
}

func TestDefaultAuthHooks_OnSessionDestroy(t *testing.T) {
	hooks := &DefaultAuthHooks{}
	err := hooks.OnSessionDestroy("token")
	assert.Error(t, err)
	assert.EqualError(t, err, "on session destroy hook not implemented")
}

func TestWithAuthHooks(t *testing.T) {
	// Setup
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})
	hooks := &DefaultAuthHooks{}

	// Apply WithAuthHooks app layer
	s.UpdateAppLayer([]AppLayer{WithAuthHooks(hooks)})

	// Assert that hooks are set
	if s.Hooks.Auth != hooks {
		t.Error("Auth hooks not set correctly")
	}
}

func TestHandleAuthLogin_BasicAuth(t *testing.T) {
	// Setup
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})

	providers := []Provider{
		{
			Name: "basic",
		},
	}

	sessionConfig := &SessionConfig{
		CookieName:      "test-cookie",
		CookieDomain:    "localhost",
		CookieSecure:    false,
		SessionDuration: time.Hour,
	}

	s.UpdateAppLayer([]AppLayer{WithAuth(providers, sessionConfig)})

	// Mock gin context and request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/auth/basic", nil)
	c.Request = req

	// Set the provider parameter in gin context
	c.Params = []gin.Param{{Key: "provider", Value: "basic"}}

	// Set basic auth credentials
	req.SetBasicAuth("testuser", "testpass")

	// Mock auth hooks - using DefaultAuthHooks which returns "not implemented"
	s.Hooks.Auth = &DefaultAuthHooks{s: s}

	// Call handler
	HandleAuthLogin(s, providers, sessionConfig.CookieName, sessionConfig.CookieDomain, sessionConfig.CookieSecure)(c)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code, "Should return unauthorized when using DefaultAuthHooks")
}

func TestHandleAuthLogin_OAuth(t *testing.T) {
	// Setup
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})

	providers := []Provider{
		{
			Name:         "google",
			ClientId:     "test-client-id",
			ClientSecret: "test-client-secret",
			Callback:     "http://localhost:3000/auth/google/callback",
		},
	}

	sessionConfig := &SessionConfig{
		CookieName:      "test-cookie",
		CookieDomain:    "localhost",
		CookieSecure:    false,
		SessionDuration: time.Hour,
	}

	s.UpdateAppLayer([]AppLayer{WithAuth(providers, sessionConfig)})

	// Mock gin context and request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/auth/google", nil)
	c.Request = req
	c.Params = []gin.Param{{Key: "provider", Value: "google"}}

	// Call handler
	HandleAuthLogin(s, providers, sessionConfig.CookieName, sessionConfig.CookieDomain, sessionConfig.CookieSecure)(c)

	// Assertions
	assert.Equal(t, http.StatusSeeOther, w.Code)
}

func TestHandleAuthLogin_ProviderNotFound(t *testing.T) {
	// Setup
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})

	providers := []Provider{}

	sessionConfig := &SessionConfig{
		CookieName:      "test-cookie",
		CookieDomain:    "localhost",
		CookieSecure:    false,
		SessionDuration: time.Hour,
	}

	s.UpdateAppLayer([]AppLayer{WithAuth(providers, sessionConfig)})

	// Mock gin context and request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/auth/unknown", nil)
	c.Request = req

	// Call handler
	HandleAuthLogin(s, providers, sessionConfig.CookieName, sessionConfig.CookieDomain, sessionConfig.CookieSecure)(c)

	// Assertions
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestEncodeDecodeStateString(t *testing.T) {
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})
	originalState := []byte(`{"return_to": "/dashboard"}`)

	encodedState := EncodeStateString(s, originalState)
	decodedState, err := DecodeStateString(encodedState)

	assert.NoError(t, err)
	assert.Equal(t, originalState, decodedState)

	// Test with encryption key
	os.Setenv("ENCRYPTION_KEY", "6368616e676520746869732070617373")
	defer os.Unsetenv("ENCRYPTION_KEY")

	encodedState = EncodeStateString(s, originalState)
	decodedState, err = DecodeStateString(encodedState)

	assert.NoError(t, err)
	assert.Equal(t, originalState, decodedState)

	// Test decode failure
	_, err = DecodeStateString("invalid-state")
	assert.Error(t, err)
}

func TestHandleAuthLogout(t *testing.T) {
	// Setup
	cookieName := "test-cookie"
	cookieDomain := "localhost"
	cookieSecure := false

	// Mock gin context and request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/auth/logout", nil)
	c.Request = req

	// Call handler
	HandleAuthLogout(cookieName, cookieDomain, cookieSecure)(c)

	// Assertions
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/", w.Header().Get("Location"))

	// Check cookie is cleared
	cookie := w.Header().Get("Set-Cookie")
	assert.Contains(t, cookie, "test-cookie=")
	assert.Contains(t, cookie, "Max-Age=0")

	// Test with redirect
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	req = httptest.NewRequest("GET", "/auth/logout?redirect=/login", nil)
	c.Request = req

	HandleAuthLogout(cookieName, cookieDomain, cookieSecure)(c)

	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

func TestNewAuthConfig(t *testing.T) {
	// Setup
	ctx := context.Background()
	clientId := "test-client-id"
	clientSecret := "test-client-secret"
	cookieName := "test-cookie"
	redirect := "http://localhost:3000/auth/test/callback"
	providerName := "google"

	// Create auth config
	authConfig := NewAuthConfig(ctx, clientId, clientSecret, cookieName, redirect, providerName)

	// Assertions
	assert.NotNil(t, authConfig)
	assert.NotNil(t, authConfig.Config)
	assert.NotNil(t, authConfig.Verifier)
	assert.NotNil(t, authConfig.CookieHandler)
	assert.Equal(t, cookieName, authConfig.AuthCookieName)
}

func TestCheckKeys(t *testing.T) {
	// Test case 1: Keys not set
	CheckKeys()

	// Test case 2: Invalid keys
	os.Setenv("SECURE_COOKIE_HASH_KEY", "invalid")
	os.Setenv("SECURE_COOKIE_BLOCK_KEY", "invalid")
	defer func() {
		os.Unsetenv("SECURE_COOKIE_HASH_KEY")
		os.Unsetenv("SECURE_COOKIE_BLOCK_KEY")
	}()

	assert.Panics(t, func() { CheckKeys() }, "should panic due to invalid keys")

	setSecureCookieKeys()
	defer func() {
		os.Unsetenv("SECURE_COOKIE_HASH_KEY")
		os.Unsetenv("SECURE_COOKIE_BLOCK_KEY")
	}()

	assert.NotPanics(t, func() { CheckKeys() }, "should not panic with valid keys")
}

func TestGetProviderIssuer(t *testing.T) {
	assert.Equal(t, "https://accounts.google.com", getProviderIssuer("google"))
	assert.Equal(t, "https://accounts.google.com", getProviderIssuer("unknown"))
}

func TestCookieContents_DeserialiseCookie(t *testing.T) {
	// Setup
	cookieString := `{"Email":"test@example.com","UserId":"123","SessionId":"session-id","IsLoggedIn":true,"ExpiresOn":"2024-01-01T00:00:00Z"}`
	cc := &CookieContents{}

	// Deserialise cookie
	deserialisedCC, err := cc.DeserialiseCookie(cookieString)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", deserialisedCC.Email)
	assert.Equal(t, "123", deserialisedCC.UserId)
	assert.Equal(t, "session-id", deserialisedCC.SessionId)
	assert.True(t, deserialisedCC.IsLoggedIn)

	// Test case 2: Invalid cookie string
	cookieString = "invalid"
	_, err = cc.DeserialiseCookie(cookieString)
	assert.Error(t, err)
}

func TestCookieHandler_SetCookieHandler(t *testing.T) {
	// Ensure secure cookie keys are set
	setSecureCookieKeys()
	defer func() {
		os.Unsetenv("SECURE_COOKIE_HASH_KEY")
		os.Unsetenv("SECURE_COOKIE_BLOCK_KEY")
	}()

	ch := NewCookieHandler()
	cookieName := "test-cookie"
	domain := "localhost"
	secure := false
	value := &CookieContents{
		Email:      "test@example.com",
		UserId:     "123",
		SessionId:  "session-id",
		IsLoggedIn: true,
		ExpiresOn:  time.Now().Add(time.Hour),
	}

	// Mock gin context and request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/test", nil)
	c.Request = req

	// Set cookie
	err := ch.SetCookieHandler(c, value, "test", cookieName, domain, secure)

	// Assertions
	assert.NoError(t, err)
	assert.NotEmpty(t, w.Header().Get("Set-Cookie"))

	// Test with encryption key
	os.Setenv("ENCRYPTION_KEY", "6368616e676520746869732070617373")
	defer os.Unsetenv("ENCRYPTION_KEY")

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	req = httptest.NewRequest("GET", "/test", nil)
	c.Request = req

	err = ch.SetCookieHandler(c, value, "test", cookieName, domain, secure)
	assert.NoError(t, err)
	assert.NotEmpty(t, w.Header().Get("Set-Cookie"))
}

func TestCookieHandler_ReadCookieHandler(t *testing.T) {
	// Ensure secure cookie keys are set
	setSecureCookieKeys()
	defer func() {
		os.Unsetenv("SECURE_COOKIE_HASH_KEY")
		os.Unsetenv("SECURE_COOKIE_BLOCK_KEY")
	}()

	// Setup
	ch := NewCookieHandler()
	cookieName := "test-cookie"

	// Mock gin context and request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/test", nil)
	c.Request = req

	// Test case 1: No cookie
	_, err := ch.ReadCookieHandler(c, cookieName)
	assert.Error(t, err)

	// Test case 2: Invalid cookie
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "invalid"})
	_, err = ch.ReadCookieHandler(c, cookieName)
	assert.Error(t, err)

	// Test case 3: Valid cookie
	value := &CookieContents{
		Email:      "test@example.com",
		UserId:     "123",
		SessionId:  "session-id",
		IsLoggedIn: true,
		ExpiresOn:  time.Now().Add(time.Hour),
	}

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	req = httptest.NewRequest("GET", "/test", nil)
	c.Request = req

	err = ch.SetCookieHandler(c, value, "test", cookieName, "localhost", false)
	assert.NoError(t, err)

	cookies := w.Result().Header.Values("Set-Cookie")
	req.Header.Set("Cookie", strings.Join(cookies, ";"))

	contents, err := ch.ReadCookieHandler(c, cookieName)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", contents.Email)
	assert.Equal(t, "123", contents.UserId)
	assert.Equal(t, "session-id", contents.SessionId)
	assert.True(t, contents.IsLoggedIn)

	// Test with encryption key
	os.Setenv("ENCRYPTION_KEY", "6368616e676520746869732070617373")
	defer os.Unsetenv("ENCRYPTION_KEY")

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	req = httptest.NewRequest("GET", "/test", nil)
	c.Request = req

	err = ch.SetCookieHandler(c, value, "test", cookieName, "localhost", false)
	assert.NoError(t, err)

	cookies = w.Result().Header.Values("Set-Cookie")
	req.Header.Set("Cookie", strings.Join(cookies, ";"))

	contents, err = ch.ReadCookieHandler(c, cookieName)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", contents.Email)
	assert.Equal(t, "123", contents.UserId)
	assert.Equal(t, "session-id", contents.SessionId)
	assert.True(t, contents.IsLoggedIn)
}

func TestGenerateEncryptionKey(t *testing.T) {
	key, err := GenerateEncryptionKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, key)
	assert.Len(t, key, 64) // Hex encoded 32 bytes
}

func TestWithPublicPaths(t *testing.T) {
	// Setup
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})
	config := PublicPathConfig{
		Exact:  []string{"/public"},
		Prefix: []string{"/prefix"},
	}

	// Apply WithPublicPaths app layer
	s.UpdateAppLayer([]AppLayer{WithPublicPaths(config)})

	// Assert that public paths are set
	assert.True(t, s.PublicPaths["/public"])
	assert.True(t, s.PublicPaths["/prefix/*"])
}

func TestServer_isPublicPath(t *testing.T) {
	// Setup
	s := NewServer([]Option{SetSecretKey([]byte("test-secret-key"))})
	config := PublicPathConfig{
		Exact:  []string{"/public"},
		Prefix: []string{"/prefix"},
	}

	s.UpdateAppLayer([]AppLayer{WithPublicPaths(config)})

	// Test cases
	assert.True(t, s.isPublicPath("/public"))
	assert.True(t, s.isPublicPath("/prefix/resource"))
	assert.False(t, s.isPublicPath("/private"))
	assert.True(t, s.isPublicPath("/auth/login"))
}

func TestGenerateCSRFToken(t *testing.T) {
	token, err := GenerateCSRFToken()
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestIsTrustedSource(t *testing.T) {
	// Test case 1: Internal IP
	req := &http.Request{
		RemoteAddr: "127.0.0.1:8080",
	}
	assert.True(t, IsTrustedSource(req))

	// Test case 2: Trusted User Agent
	req = &http.Request{
		RemoteAddr: "192.168.1.1:8080",
		Header:     http.Header{"User-Agent": []string{"InternalServiceClient"}},
	}
	assert.True(t, IsTrustedSource(req))

	// Test case 3: X-Internal-Request header
	req = &http.Request{
		RemoteAddr: "192.168.1.1:8080",
		Header:     http.Header{"X-Internal-Request": []string{"true"}},
	}
	assert.True(t, IsTrustedSource(req))

	// Test case 4: Not trusted
	req = &http.Request{
		RemoteAddr: "192.168.1.1:8080",
	}
	assert.False(t, IsTrustedSource(req))
}

func TestGetSession(t *testing.T) {
	// Mock gin context and request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/test", nil)
	c.Request = req

	// Test case 1: No session in context
	_, err := GetSession(c)
	assert.Error(t, err)

	// Test case 2: Invalid session type
	c.Set(string(sessionKey), "invalid")
	_, err = GetSession(c)
	assert.Error(t, err)

	// Test case 3: Valid session
	session := &Session{Email: "test@example.com"}
	c.Set(string(sessionKey), session)
	retrievedSession, err := GetSession(c)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", retrievedSession.Email)
}

func TestMustGetSession(t *testing.T) {
	// Mock gin context and request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/test", nil)
	c.Request = req

	// Test case 1: No session in context
	_, err := MustGetSession(c)
	assert.Error(t, err)

	// Test case 2: Valid session
	session := &Session{Email: "test@example.com"}
	c.Set(string(sessionKey), session)
	retrievedSession, err := MustGetSession(c)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", retrievedSession.Email)
}

func TestRedirectError(t *testing.T) {
	err := &RedirectError{
		RedirectURL: "/login",
		StatusCode:  http.StatusFound,
	}

	assert.Equal(t, "redirect required to: /login", err.Error())
}

func TestDefaultAuthErrorHandler_RedirectError(t *testing.T) {
	// Mock gin context and request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/test", nil)
	c.Request = req

	// Create a redirect error
	err := &RedirectError{
		RedirectURL: "/login",
		StatusCode:  http.StatusFound,
	}

	// Call the error handler
	DefaultAuthErrorHandler(c, err)

	// Assertions
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

func TestDefaultAuthErrorHandler_Unauthorized(t *testing.T) {
	// Mock gin context and request
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/test", nil)
	c.Request = req

	// Create a generic error
	err := fmt.Errorf("generic error")

	// Call the error handler
	DefaultAuthErrorHandler(c, err)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
