package EpicServer

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

type Auth struct {
	Provider       *oidc.Provider
	Config         *oauth2.Config
	Verifier       *oidc.IDTokenVerifier
	CookieHandler  *CookieHandler
	AuthCookieName string
	RedirectOnFail string
}

type SessionConfig struct {
	CookieName      string
	CookieDomain    string
	CookieMaxAge    int
	CookieSecure    bool
	CookieHTTPOnly  bool
	SessionDuration time.Duration
	ErrorHandler    AuthErrorHandler
}

type Claims struct {
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Verified    bool     `json:"email_verified"`
	UserID      string   `json:"user_id"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	Picture     string   `json:"picture"`
}

type Provider struct {
	Name         string
	ClientId     string
	ClientSecret string
	Callback     string
}

// Add configuration type for public paths
type PublicPathConfig struct {
	Exact  []string // Exact match paths
	Prefix []string // Prefix match paths
}

// the Authentication is going to be a large configurable ServerOption
func WithAuth(
	providers []Provider,
	sessionConfig *SessionConfig,
) AppLayer {
	return func(s *Server) {
		s.AuthConfigs = make(map[string]*Auth)

		// Create auth configs once
		for _, provider := range providers {
			if provider.Name != "basic" && (provider.ClientId == "" || provider.ClientSecret == "" || provider.Name == "" || provider.Callback == "") {
				panic("Make sure that providers have valid fields.")
			}

			authConfig := NewAuthConfig(
				context.Background(),
				provider.ClientId,
				provider.ClientSecret,
				sessionConfig.CookieName,
				provider.Callback,
				provider.Name,
			)
			s.AuthConfigs[provider.Name] = authConfig
		}

		RegisterAuthRoutes(s, providers, sessionConfig.CookieName, sessionConfig.CookieDomain, sessionConfig.CookieSecure)

		// Add module-based logging
		authLogger := s.Logger.WithModule("auth")
		authLogger.Info("Authentication configured",
			F("providers", len(providers)),
			F("cookie_name", sessionConfig.CookieName),
			F("cookie_domain", sessionConfig.CookieDomain))
	}
}

type RedirectError struct {
	RedirectURL string
	StatusCode  int
}

func (e *RedirectError) Error() string {
	return fmt.Sprintf("redirect required to: %s", e.RedirectURL)
}

type AuthErrorHandler func(*gin.Context, error)

func DefaultAuthErrorHandler(c *gin.Context, err error) {
	if redirectErr, ok := err.(*RedirectError); ok {
		c.Redirect(redirectErr.StatusCode, redirectErr.RedirectURL)
		c.Abort()
		return
	}
	c.AbortWithStatus(http.StatusUnauthorized)
}

func RegisterAuthRoutes(s *Server, providers []Provider, cookieName string, domain string, secure bool) {
	s.Engine.GET("/auth/:provider", HandleAuthLogin(s, providers, cookieName, domain, secure))
	s.Engine.GET("/auth/:provider/callback", HandleAuthCallback(s, providers, cookieName, domain, secure, s.Hooks.Auth))
	s.Engine.GET("/auth/logout", HandleAuthLogout(cookieName, domain, secure))
}

func WithAuthMiddleware(config SessionConfig) AppLayer {
	return func(s *Server) {
		s.Engine.Use(func(c *gin.Context) {
			// Skip auth for public routes if needed
			if s.isPublicPath(c.Request.URL.Path) {
				c.Next()
				return
			}

			// Create module-based logger
			authMiddlewareLogger := s.Logger.WithModule("auth.middleware")

			session, err := GetSessionFromCookie(s, c, config.CookieName)
			if err != nil {
				authMiddlewareLogger.Debug("Authentication failed",
					F("path", c.Request.URL.Path),
					F("error", err.Error()))

				if config.ErrorHandler != nil {
					config.ErrorHandler(c, err)
				} else {
					c.AbortWithStatus(http.StatusUnauthorized)
				}
				return
			}

			authMiddlewareLogger.Debug("User authenticated",
				F("email", session.Email))

			// Set user in context
			c.Set(string(sessionKey), session)
			c.Next()
		})

		// Add module-based logging
		authLogger := s.Logger.WithModule("auth")
		authLogger.Info("Auth middleware configured",
			F("cookie_name", config.CookieName),
			F("cookie_domain", config.CookieDomain))
	}
}

func GetSessionFromCookie(s *Server, c *gin.Context, cookieName string) (*Session, error) {
	// Create module-based logger
	sessionLogger := s.Logger.WithModule("auth.session")

	providerCookie, err := c.Cookie("provider")
	if err != nil {
		sessionLogger.Debug("Provider cookie not found", F("error", err.Error()))
		return nil, err
	}

	cookie, err := s.AuthConfigs[providerCookie].CookieHandler.ReadCookieHandler(c, cookieName)
	if err != nil {
		sessionLogger.Debug("Failed to read cookie",
			F("provider", providerCookie),
			F("cookie_name", cookieName),
			F("error", err.Error()))
		return nil, err
	}

	// Validate session/token using the hooks
	user, err := s.Hooks.Auth.OnSessionValidate(cookie)
	if err != nil {
		sessionLogger.Debug("Session validation failed",
			F("email", cookie.Email),
			F("error", err.Error()))
		return nil, err
	}

	sessionLogger.Debug("Session validated successfully",
		F("email", cookie.Email))

	session := &Session{
		User:      user,
		Token:     cookie.SessionId,
		Email:     cookie.Email,
		ExpiresOn: cookie.ExpiresOn,
		// Add other session fields as needed
	}

	return session, nil
}

type AuthenticationHooks interface {
	// OnUserCreate is a hook for the consumer to create their user and return the userID to be saved to the cookie
	OnUserCreate(user Claims) (string, error)
	GetUserOrCreate(user Claims) (*CookieContents, error)
	OnAuthenticate(username, password string, state OAuthState) (bool, error)
	OnUserGet(userID string) (any, error)
	OnSessionValidate(sessionToken *CookieContents) (interface{}, error)
	OnSessionCreate(userID string) (string, error)
	OnSessionDestroy(sessionToken string) error
	OnOAuthCallbackSuccess(ctx *gin.Context, state OAuthState) error
}

// Optional: Provide a base implementation with no-op methods
type DefaultAuthHooks struct {
	s *Server
}

func (d *DefaultAuthHooks) OnOAuthCallbackSuccess(ctx *gin.Context, state OAuthState) error {
	fmt.Println("default oauthcallbacksucess")
	return nil
}

// OnUserCreate for when the session is validated and we need to check or create a user if its been created
func (d *DefaultAuthHooks) GetUserOrCreate(user Claims) (*CookieContents, error) {
	return &CookieContents{
		UserId: user.UserID,
		Email:  user.Email,
		SessionId: func() string {
			b := make([]byte, 32)
			rand.Read(b)
			return base64.StdEncoding.EncodeToString(b)
		}(),
		IsLoggedIn: true,
		ExpiresOn:  time.Now().Add(time.Duration(1 * time.Hour)),
	}, nil
}

// OnUserCreate for when the session is validated and we need to check or create a user if its been created
func (d *DefaultAuthHooks) OnUserCreate(user Claims) (string, error) {
	return user.UserID, nil
}

// OnAuthenticate should only really be used with password authentication
func (d *DefaultAuthHooks) OnAuthenticate(username, password string, state OAuthState) (bool, error) {
	return false, fmt.Errorf("on authenticate hook not implemented")
}

// OnUserGet retrieves the user based on the userID
func (d *DefaultAuthHooks) OnUserGet(userID string) (any, error) {
	return "", fmt.Errorf("on user get hook not implemented")
}

// OnSessionValidate validates the session token and returns the userID
func (d *DefaultAuthHooks) OnSessionValidate(sessionToken *CookieContents) (interface{}, error) {
	return "", fmt.Errorf("on session validate hook not implemented")
}

// OnSessionCreate creates a new session for the user and returns the session token
func (d *DefaultAuthHooks) OnSessionCreate(userID string) (string, error) {
	return "", fmt.Errorf("on session create hook not implemented")
}

// OnSessionDestroy destroys the session token
func (d *DefaultAuthHooks) OnSessionDestroy(sessionToken string) error {
	return fmt.Errorf("on session destroy hook not implemented")
}

// WithAuthHooks allows you to define hooks to listen into when creating the server and customising how the user is stored
func WithAuthHooks(hooks AuthenticationHooks) AppLayer {
	return func(s *Server) {
		s.Hooks.Auth = hooks

		// Add module-based logging
		authLogger := s.Logger.WithModule("auth.hooks")
		authLogger.Debug("Auth hooks configured")
	}
}

type OAuthState struct {
	CookieDomainOverride string                 `json:"cookie_domain_override"`
	ReturnTo             string                 `json:"return_to"`
	Custom               map[string]interface{} `json:"custom"`
}

func HandleAuthLogin(s *Server, providers []Provider, cookieName string, domain string, secure bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Create module-based logger
		loginLogger := s.Logger.WithModule("auth.login")

		providerParam := ctx.Param("provider")
		loginLogger.Debug("Auth login request", F("provider", providerParam))

		// if there is a app callback param in the original request, pass on to the oauth
		var options []oauth2.AuthCodeOption

		state := "state"
		var cState OAuthState

		if ctx.Query("custom_state") != "" {
			customState := ctx.Query("custom_state")

			err := json.Unmarshal([]byte(customState), &cState)
			if err != nil {
				loginLogger.Error("Error parsing custom state", F("error", err.Error()))
				ctx.AbortWithError(http.StatusInternalServerError, err)
				return
			}

			stateJSON, err := json.Marshal(cState)
			if err != nil {
				loginLogger.Error("Error marshalling custom state", F("error", err.Error()))
				ctx.AbortWithError(http.StatusInternalServerError, err)
				return
			}

			state = EncodeStateString(s, stateJSON)
		}

		// this allows custom authentication domain for configurable frontend,
		// helpful for multi tennant applications on different domains.
		// In the hook when authenticating you will want to check the domain is valid
		// ! RESEARCH POTENTIAL SECURITY RISK AROUND MANIPULATING
		if cState.CookieDomainOverride != "" {
			domain = cState.CookieDomainOverride
		}

		if authConfig, exists := s.AuthConfigs[providerParam]; exists {
			if providerParam == "basic" {
				// Basic auth provider
				username, password, ok := ctx.Request.BasicAuth()

				if !ok {
					loginLogger.Warn("Basic auth failed - no credentials provided")
					ctx.AbortWithStatus(http.StatusUnauthorized)
					return
				}

				authenticated, err := s.Hooks.Auth.OnAuthenticate(username, password, cState)
				if err != nil {
					loginLogger.Error("Error authenticating", F("error", err.Error()))
					ctx.AbortWithError(http.StatusUnauthorized, err)
					return
				}

				if !authenticated {
					loginLogger.Warn("Unauthorized login attempt", F("username", username))
					ctx.AbortWithStatus(http.StatusUnauthorized)
					return
				}

				// Create a session
				contents, err := s.Hooks.Auth.GetUserOrCreate(Claims{
					Email: username,
				})

				if err != nil {
					loginLogger.Error("Error creating session", F("error", err.Error()))
					ctx.AbortWithError(http.StatusInternalServerError, err)
					return
				}

				err = authConfig.CookieHandler.SetCookieHandler(
					ctx,
					contents,
					"basic",
					cookieName,
					domain,
					secure,
				)

				if err != nil {
					loginLogger.Error("Error setting cookie", F("error", err.Error()))
					ctx.AbortWithError(http.StatusInternalServerError, err)
					return
				}

				loginLogger.Info("Basic auth successful", F("username", username))
				return
			}

			loginLogger.Debug("Redirecting to OAuth provider",
				F("provider", providerParam),
				F("state", state != "state"))
			ctx.Redirect(http.StatusSeeOther, authConfig.Config.AuthCodeURL(state, options...))
			return
		}

		loginLogger.Warn("Provider not found", F("provider", providerParam))
		ctx.JSON(http.StatusNotFound, gin.H{"provider": "doesn't exist"})
	}
}

func EncodeStateString(s *Server, stateString []byte) string {
	secret := os.Getenv("ENCRYPTION_KEY")
	if secret == "" {
		return base64.URLEncoding.EncodeToString(stateString)
	}

	key, _ := hex.DecodeString(secret)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(string(stateString)))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], stateString)

	// make sure signed and protected using hmac
	h := hmac.New(sha256.New, key)
	h.Write(ciphertext)
	mac := h.Sum(nil)

	final := append(ciphertext, mac...)

	return base64.RawURLEncoding.EncodeToString(final)
}

func DecodeStateString(stateString string) ([]byte, error) {
	secret := os.Getenv("ENCRYPTION_KEY")
	if secret == "" {
		return base64.URLEncoding.DecodeString(stateString)
	}

	key, _ := hex.DecodeString(secret)
	ciphertext, err := base64.RawURLEncoding.DecodeString(stateString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode state: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	encryptedData := ciphertext[aes.BlockSize : len(ciphertext)-32]
	messageMAC := ciphertext[len(ciphertext)-32:]

	// Verify HMAC
	h := hmac.New(sha256.New, key)
	h.Write(ciphertext[:len(ciphertext)-32])
	expectedMAC := h.Sum(nil)
	if !hmac.Equal(messageMAC, expectedMAC) {
		return nil, fmt.Errorf("invalid MAC")
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encryptedData, encryptedData)

	return encryptedData, nil
}

func HandleAuthCallback(s *Server, providers []Provider, cookiename string, domain string, secure bool, hooks AuthenticationHooks) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Create module-based logger
		callbackLogger := s.Logger.WithModule("auth.callback")

		prov := ctx.Param("provider")
		callbackLogger.Debug("Auth callback request", F("provider", prov))

		authConfig, exists := s.AuthConfigs[prov]
		if !exists {
			callbackLogger.Warn("Provider not found", F("provider", prov))
			ctx.JSON(http.StatusNotFound, gin.H{"provider": "doesn't exist"})
			return
		}

		// Use the stored auth config
		oauth2Token, err := authConfig.Config.Exchange(ctx, ctx.Query("code"))
		if err != nil {
			callbackLogger.Error("Failed to exchange token", F("error", err.Error()))
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			// handle missing token
			callbackLogger.Error("Missing ID token in OAuth response")
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := authConfig.Verifier.Verify(ctx, rawIDToken)
		if err != nil {
			// handle error
			callbackLogger.Error("Failed to verify ID token", F("error", err.Error()))
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		// Extract custom claims
		var claims Claims

		if err := idToken.Claims(&claims); err != nil {
			// handle error
			callbackLogger.Error("Failed to extract claims", F("error", err.Error()))
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		callbackLogger.Debug("Processing OAuth claims",
			F("email", claims.Email),
			F("verified", claims.Verified))

		// event hook needs to be called here
		contents, err := hooks.GetUserOrCreate(claims)
		if err != nil {
			callbackLogger.Error("Failed to get or create user", F("error", err.Error()))
		}

		err = authConfig.CookieHandler.SetCookieHandler(
			ctx,
			contents,
			prov,
			cookiename,
			domain,
			secure,
		)

		ctx.SetCookie(
			"provider",
			prov,
			int((time.Hour * 24 * 7).Seconds()),
			"/",
			domain,
			secure,
			true,
		)

		if err != nil {
			callbackLogger.Error("Error setting cookie", F("error", err.Error()))
			return
		}

		if ctx.Query("state") != "state" {
			decodedString, err := DecodeStateString(ctx.Query("state"))
			if err != nil {
				callbackLogger.Error("Error decoding state string", F("error", err.Error()))
				// handle error
				ctx.AbortWithError(http.StatusInternalServerError, err)
				return
			}

			var stateStruct OAuthState

			err = json.Unmarshal(decodedString, &stateStruct)
			if err != nil {
				callbackLogger.Error("Error unmarshalling string", F("error", err.Error()))
				ctx.AbortWithError(http.StatusInternalServerError, err)
				return
			}

			callbackLogger.Debug("Handling custom OAuth callback",
				F("return_to", stateStruct.ReturnTo))
			hooks.OnOAuthCallbackSuccess(ctx, stateStruct)
			return
		}

		callbackLogger.Info("Authentication successful",
			F("provider", prov),
			F("email", claims.Email))
		ctx.Redirect(http.StatusSeeOther, "/")
	}
}

// HandleAuthLogout registers handler for the route that provides functionality to frontend for logging out.
func HandleAuthLogout(cookiename string, cookieDomain string, cookieSecure bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Create module-based logger - we need to get the server from context
		var logoutLogger Logger
		if s, exists := ctx.Get("server"); exists {
			if server, ok := s.(*Server); ok {
				logoutLogger = server.Logger.WithModule("auth.logout")
			}
		}

		ctx.SetCookie(
			cookiename,
			"",
			-1,
			"/",
			cookieDomain,
			cookieSecure,
			true,
		)

		if logoutLogger != nil {
			logoutLogger.Info("User logged out")
		}

		if ctx.Query("redirect") != "" {
			ctx.Redirect(http.StatusSeeOther, ctx.Query("redirect"))
			return
		}

		ctx.Redirect(http.StatusSeeOther, "/")
	}
}

// NewAuthConfig creates and spits out an auth config
func NewAuthConfig(
	ctx context.Context,
	clientId string,
	clientSecret string,
	cookieName string,
	redirect string,
	providerName string,
) *Auth {
	CheckKeys()

	ch := NewCookieHandler()

	auth := Auth{
		Provider:       nil,
		Config:         &oauth2.Config{},
		Verifier:       nil,
		CookieHandler:  ch,
		AuthCookieName: cookieName,
	}

	if providerName == "basic" {
		return &auth
	}

	issuer := getProviderIssuer(providerName)

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		// handle error
		log.Printf("error creating auth provider: %v", err)
		return nil
	}

	// Configure an OpenID Connect aware OAuth2 client.
	auth.Config = &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  redirect,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	auth.Verifier = provider.Verifier(&oidc.Config{ClientID: clientId})

	return &auth
}

// CheckKeys is a helper method that only ensures the validity of a HASH AND BLOCK key
func CheckKeys() {
	// Get the base64-encoded keys from environment variables
	hashKeyBase64 := os.Getenv("SECURE_COOKIE_HASH_KEY")
	blockKeyBase64 := os.Getenv("SECURE_COOKIE_BLOCK_KEY")

	if len(hashKeyBase64) <= 0 || len(blockKeyBase64) <= 0 {
		fmt.Println("Secure cookies keys not set")
		return
	}

	// Decode the base64-encoded keys
	hashKey, err := base64.StdEncoding.DecodeString(hashKeyBase64)
	if err != nil {
		panic("Failed to decode hash key: " + err.Error())
	}

	blockKey, err := base64.StdEncoding.DecodeString(blockKeyBase64)
	if err != nil {
		panic("Failed to decode block key: " + err.Error())
	}

	// Ensure the keys are of valid length for AES
	if len(hashKey) != 32 || len(blockKey) != 32 {
		panic("Keys must be 32 bytes long")
	}
}

// here we can determine the issuer url
func getProviderIssuer(provider string) string {

	switch provider {
	case "google":
		return "https://accounts.google.com"
	default:
		return "https://accounts.google.com"
	}
}

/// COOKIEEEES -----------------------

type CookieHandler struct {
	SecureCookie *securecookie.SecureCookie
}

// NewCookieHandler creates a new CookieHandler
func NewCookieHandler() *CookieHandler {
	secureCookieHashKey := os.Getenv("SECURE_COOKIE_HASH_KEY")
	secureCookieBlockKey := os.Getenv("SECURE_COOKIE_BLOCK_KEY")

	hashKey, err := base64.StdEncoding.DecodeString(secureCookieHashKey)
	if err != nil {
		panic("Failed to decode hash key: " + err.Error())
	}

	blockKey, err := base64.StdEncoding.DecodeString(secureCookieBlockKey)
	if err != nil {
		panic("Failed to decode block key: " + err.Error())
	}

	return &CookieHandler{
		SecureCookie: securecookie.New(hashKey, blockKey),
	}
}

// Cookie Contents struct
type CookieContents struct {
	Email      string
	UserId     string
	SessionId  string
	IsLoggedIn bool
	ExpiresOn  time.Time
}

func (cc *CookieContents) DeserialiseCookie(cookieString string) (*CookieContents, error) {
	err := json.Unmarshal([]byte(cookieString), cc)
	if err != nil {
		return nil, err
	}

	return cc, nil
}

func (ch *CookieHandler) SetCookieHandler(ctx *gin.Context, value *CookieContents, provider string, cookieName string, domain string, secure bool) error {
	// Encode the cookie using securecookie
	encoded, err := ch.SecureCookie.Encode(cookieName, value)
	if err != nil {
		return err
	}

	// Set cookie with the encoded value
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     cookieName,
		Value:    encoded,
		Path:     "/",
		Domain:   domain,
		Expires:  value.ExpiresOn,
		Secure:   secure,
		HttpOnly: true,
	})
	return nil
}

func (ch *CookieHandler) ReadCookieHandler(ctx *gin.Context, cookieName string) (*CookieContents, error) {
	// Retrieve the cookie
	cookie, err := ctx.Cookie(cookieName)
	if err != nil {
		return nil, err
	}

	// Decode the cookie
	var value CookieContents
	err = ch.SecureCookie.Decode(cookieName, cookie, &value)
	if err != nil {
		return nil, err
	}

	return &value, nil
}

// GenerateEncryptionKey generates a 32-byte (256-bit) key suitable for AES-256 encryption
func GenerateEncryptionKey() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("failed to generate random key: %v", err)
	}
	return hex.EncodeToString(key), nil
}

// AppLayer function to configure public paths
func WithPublicPaths(config PublicPathConfig) AppLayer {
	return func(s *Server) {
		s.PublicPaths = make(map[string]bool)

		// Add exact matches
		for _, path := range config.Exact {
			s.PublicPaths[path] = true
		}

		// Store prefix matches with special suffix
		for _, prefix := range config.Prefix {
			s.PublicPaths[prefix+"/*"] = true
		}
	}
}

func (s *Server) isPublicPath(path string) bool {
	if strings.HasPrefix(path, "/auth") {
		return true
	}

	// Check exact matches first
	if s.PublicPaths[path] {
		return true
	}

	// Check prefix matches
	for storedPath := range s.PublicPaths {
		if strings.HasSuffix(storedPath, "/*") {
			prefix := strings.TrimSuffix(storedPath, "/*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	}

	return false
}

func GenerateCSRFToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(token), nil
}

// IsTrustedSource IsTrustedSource checks if the request is from a trusted source
func IsTrustedSource(r *http.Request) bool {
	// Example: Bypass CSRF check for internal IP addresses
	internalIPs := []string{"127.0.0.1", "::1"}
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		fmt.Println(err)
		return false
	}

	for _, ip := range internalIPs {
		if clientIP == ip {
			return true
		}
	}

	// Example: Bypass CSRF check for specific user agents
	trustedUserAgents := []string{"InternalServiceClient"}
	userAgent := r.UserAgent()

	for _, ua := range trustedUserAgents {
		if userAgent == ua {
			return true
		}
	}

	// Example: Bypass CSRF check for requests with a specific header
	return r.Header.Get("X-Internal-Request") == "true"
}

// Session represents the user's session data
type Session struct {
	User      interface{}
	Token     string
	Email     string
	ExpiresOn time.Time
	// Add other session fields as needed
}

// Context keys to avoid string collisions
type contextKey string

const (
	sessionKey contextKey = "session"
)

// Helper function to get session from context
func GetSession(c *gin.Context) (*Session, error) {
	value, exists := c.Get(string(sessionKey))
	if !exists {
		return nil, fmt.Errorf("no session found in context")
	}

	session, ok := value.(*Session)
	if !ok {
		return nil, fmt.Errorf("invalid session type in context")
	}

	return session, nil
}

// Optional: Helper for required session (panics if no session)
func MustGetSession(c *gin.Context) (*Session, error) {
	session, err := GetSession(c)
	if err != nil {
		return nil, err
	}
	return session, nil
}
