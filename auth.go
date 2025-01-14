package EpicServer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

		// 1. we need to setup oauth configs that can be used for different providers
		// 2. we need to set up WithAuth to accept provider name, client id, secret and callback
		// 3. the with auth layer should automatically set these up including routes and

	}
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

			providerCookie, err := c.Cookie("provider")
			if err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			cookie, err := s.AuthConfigs[providerCookie].CookieHandler.ReadCookieHandler(c, config.CookieName)
			if err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			// Validate session/token using the hooks
			user, err := s.Hooks.Auth.OnSessionValidate(cookie)
			if err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			session := &Session{
				User:      user,
				Token:     cookie.SessionId,
				Email:     cookie.Email,
				ExpiresOn: cookie.ExpiresOn,
				// Add other session fields as needed
			}

			// Set user in context
			c.Set(string(sessionKey), session)
			c.Next()
		})
	}
}

type AuthenticationHooks interface {
	// OnUserCreate is a hook for the consumer to create their user and return the userID to be saved to the cookie
	OnUserCreate(user Claims) (string, error)
	GetUserOrCreate(user Claims) (*CookieContents, error)
	OnAuthenticate(username, password string) (bool, error)
	OnUserGet(userID string) (any, error)
	OnSessionValidate(sessionToken *CookieContents) (interface{}, error)
	OnSessionCreate(userID string) (string, error)
	OnSessionDestroy(sessionToken string) error
}

// Optional: Provide a base implementation with no-op methods
type DefaultAuthHooks struct {
	s *Server
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
	return "", fmt.Errorf("user creation hook not implemented")
}

// OnAuthenticate should only really be used with password authentication
func (d *DefaultAuthHooks) OnAuthenticate(username, password string) (bool, error) {
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
	}
}

func HandleAuthLogin(s *Server, providers []Provider, cookieName string, domain string, secure bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		providerParam := ctx.Param("provider")

		if authConfig, exists := s.AuthConfigs[providerParam]; exists {
			if providerParam == "basic" {
				// Basic auth provider
				username, password, ok := ctx.Request.BasicAuth()

				if !ok {
					ctx.AbortWithStatus(http.StatusUnauthorized)
					return
				}

				authenticated, err := s.Hooks.Auth.OnAuthenticate(username, password)
				if err != nil {
					s.Logger.Error(err)
					ctx.AbortWithError(http.StatusInternalServerError, err)
					return
				}

				if !authenticated {
					s.Logger.Error("unauthorised")
					ctx.AbortWithStatus(http.StatusUnauthorized)
					return
				}

				// Create a session
				contents, err := s.Hooks.Auth.GetUserOrCreate(Claims{
					Email: username,
				})

				if err != nil {
					s.Logger.Error(err)
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
					s.Logger.Error(err)
					ctx.AbortWithError(http.StatusInternalServerError, err)
					return
				}

				s.Logger.Debug("Basic auth provider")
				return
			}

			ctx.Redirect(http.StatusSeeOther, authConfig.Config.AuthCodeURL("state"))
			return
		}

		ctx.JSON(http.StatusNotFound, gin.H{"provider": "doesn't exist"})
	}
}

func HandleAuthCallback(s *Server, providers []Provider, cookiename string, domain string, secure bool, hooks AuthenticationHooks) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		prov := ctx.Param("provider")

		authConfig, exists := s.AuthConfigs[prov]
		if !exists {
			ctx.JSON(http.StatusNotFound, gin.H{"provider": "doesn't exist"})
			return
		}

		// Use the stored auth config
		oauth2Token, err := authConfig.Config.Exchange(ctx, ctx.Query("code"))
		if err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			// handle missing token
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := authConfig.Verifier.Verify(ctx, rawIDToken)
		if err != nil {
			// handle error
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		// Extract custom claims
		var claims Claims

		if err := idToken.Claims(&claims); err != nil {
			// handle error
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		// event hook needs to be called here
		contents, err := hooks.GetUserOrCreate(claims)
		if err != nil {
			fmt.Println(err)
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
			return
		}

		ctx.Redirect(http.StatusSeeOther, "/")
	}
}

// HandleAuthLogout registers handler for the route that provides functionality to frontend for logging out.
func HandleAuthLogout(cookiename string, cookieDomain string, cookieSecure bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.SetCookie(
			cookiename,
			"",
			-1,
			"/",
			cookieDomain,
			cookieSecure,
			true,
		)

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
	expiry := time.Hour * 24 * 7
	value.ExpiresOn = time.Now().Add(expiry)

	// set cookie contents to json
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	encoded, err := ch.SecureCookie.Encode(cookieName, jsonValue)
	if err != nil {
		return err
	}

	ctx.SetCookie(
		cookieName,
		encoded,
		int(expiry.Seconds()),
		"/",
		domain,
		secure,
		true,
	)

	ctx.SetCookie(
		"provider",
		provider,
		int(expiry.Seconds()),
		"/",
		domain,
		secure,
		true,
	)

	return nil
}

func (ch *CookieHandler) ReadCookieHandler(ctx *gin.Context, cookieName string) (*CookieContents, error) {
	cookie, err := ctx.Cookie(cookieName)
	if err == nil {
		var value []byte
		err = ch.SecureCookie.Decode(cookieName, cookie, &value)
		if err == nil {
			var cookieContents CookieContents
			err := json.Unmarshal(value, &cookieContents)
			if err != nil {
				return &CookieContents{}, err
			}

			return &cookieContents, nil
		}
	}

	return &CookieContents{}, err
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
	return base64.StdEncoding.EncodeToString(token), nil
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
func MustGetSession(c *gin.Context) *Session {
	session, err := GetSession(c)
	if err != nil {
		panic("attempting to access session in non-authenticated context")
	}
	return session
}
