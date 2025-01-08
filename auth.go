package EpicServer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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

type AuthConfig struct {
	CookieName      string
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
func WithOAuth(
	ctx context.Context,
	providers []Provider,
	cookiename string,
	cookieDomain string,
	cookieSecure bool,
) AppLayer {
	return func(s *Server) {
		// lets loop through and make sure that each provider is valid
		for _, provider := range providers {
			if provider.ClientId == "" || provider.ClientSecret == "" || provider.Name == "" || provider.Callback == "" {
				panic("Make sure that providers have valid fields.")
			}
		}

		RegisterAuthRoutes(s, providers, cookiename, cookieDomain, cookieSecure)

		// 1. we need to setup oauth configs that can be used for different providers
		// 2. we need to set up WithAuth to accept provider name, client id, secret and callback
		// 3. the with auth layer should automatically set these up including routes and

	}
}

func WithAuthMiddleware(config AuthConfig) AppLayer {
	return func(s *Server) {
		s.engine.Use(func(c *gin.Context) {
			if skip, exists := c.Get("skip_auth"); exists && skip.(bool) {
				c.Next()
				return
			}

			// Skip auth for public routes if needed
			if s.isPublicPath(c.Request.URL.Path) {
				c.Next()
				return
			}

			// Get auth cookie
			cookie, err := c.Cookie(config.CookieName)
			if err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			// Validate session/token using the hooks
			userID, err := s.hooks.Auth.OnSessionValidate(cookie)
			if err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			// Get user using the hooks
			user, err := s.hooks.Auth.OnUserGet(userID)
			if err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			// Set user in context
			c.Set("user", user)
			c.Next()
		})
	}
}

type AuthenticationHooks interface {
	// OnUserCreate is a hook for the consumer to create their user and return the userID to be saved to the cookie
	OnUserCreate(user Claims) (string, error)
	OnAuthenticate(username, password string) (bool, error)
	OnUserGet(userID string) (*string, error)
	OnSessionValidate(sessionToken string) (string, error)
	OnSessionCreate(userID string) (string, error)
	OnSessionDestroy(sessionToken string) error
}

// Optional: Provide a base implementation with no-op methods
type DefaultAuthHooks struct{}

// OnUserCreate for when the session is validated and we need to check or create a user if its been created
func (d *DefaultAuthHooks) OnUserCreate(user Claims) (string, error) {
	return "", fmt.Errorf("user creation hook not implemented")
}

// OnAuthenticate should only really be used with password authentication
func (d *DefaultAuthHooks) OnAuthenticate(username, password string) (bool, error) {
	return false, fmt.Errorf("on authenticate hook not implemented")
}

// OnUserGet retrieves the user based on the userID
func (d *DefaultAuthHooks) OnUserGet(userID string) (*string, error) {
	return nil, fmt.Errorf("on user get hook not implemented")
}

// OnSessionValidate validates the session token and returns the userID
func (d *DefaultAuthHooks) OnSessionValidate(sessionToken string) (string, error) {
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
		s.hooks.Auth = hooks
	}
}

func RegisterAuthRoutes(s *Server, providers []Provider, cookieName string, domain string, secure bool) {
	s.engine.GET("/auth/:provider", HandleAuthGoogle(providers, cookieName))
	s.engine.GET("/auth/:provider/callback", HandleAuthGoogleCallback(providers, cookieName, domain, secure, s.hooks.Auth))
	s.engine.GET("/auth/logout", HandleAuthLogout(domain, secure))
}

func HandleAuthGoogle(providers []Provider, cookieName string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		providerParam := ctx.Param("provider")

		for _, provider := range providers {
			if provider.Name == providerParam {
				c := NewAuthConfig(
					ctx,
					provider.ClientId,
					provider.ClientSecret,
					cookieName,
					provider.Callback,
					provider.Name,
				)

				// we take the generated config and return
				// we need to add some kind of error handling somewhere here in the new auth config.
				ctx.Redirect(http.StatusSeeOther, c.Config.AuthCodeURL("state"))
			}
		}

		ctx.JSON(http.StatusNotFound, gin.H{"provider": "doesn't exist"})

	}
}

func HandleAuthGoogleCallback(providers []Provider, cookiename string, domain string, secure bool, hooks AuthenticationHooks) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		prov := ctx.Param("provider")

		for _, provider := range providers {
			if provider.Name == prov {
				c := NewAuthConfig(
					ctx,
					provider.ClientId,
					provider.ClientSecret,
					cookiename,
					provider.Callback,
					provider.Name,
				)

				// Verify state and errors.
				oauth2Token, err := c.Config.Exchange(ctx, ctx.Query("code"))
				if err != nil {
					// handle
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
				idToken, err := c.Verifier.Verify(ctx, rawIDToken)
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

				cookieContents := &CookieContents{
					Email: claims.Email,
				}

				// event hook needs to be called here
				userId, err := hooks.OnUserCreate(claims)
				if err != nil {
					fmt.Println(err)
				}

				if userId != "" {
					cookieContents.UserId = userId
				}

				err = c.CookieHandler.SetCookieHandler(
					ctx,
					cookieContents,
					"sesh_name",
					domain,
					secure,
				)

				if err != nil {
					return
				}

				ctx.Redirect(http.StatusSeeOther, "/")
			}
		}

	}
}

// HandleAuthLogout registers handler for the route that provides functionality to frontend for logging out.
func HandleAuthLogout(cookieDomain string, cookieSecure bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.SetCookie(
			"sesh_name",
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

	provider, err := oidc.NewProvider(ctx, getProviderIssuer(providerName))
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
	default:
		return "https://accounts.google.com"
	}

	return ""
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

func (ch *CookieHandler) SetCookieHandler(ctx *gin.Context, value *CookieContents, cookieName string, domain string, secure bool) error {
	expiry := time.Hour * 24 * 7
	value.ExpiresOn = time.Now().Add(expiry)

	// set cookie contents to json
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	if encoded, err := ch.SecureCookie.Encode(cookieName, jsonValue); err == nil {
		ctx.SetCookie(
			cookieName,
			encoded,
			int(expiry.Seconds()),
			"/",
			domain,
			secure,
			true,
		)

		return nil
	}

	return errors.New("error setting cookie")
}

func (ch *CookieHandler) ReadCookieHandler(ctx *gin.Context, cookieName string) (string, error) {
	cookie, err := ctx.Cookie(cookieName)
	if err == nil {
		var value []byte
		// fmt.Println("cookie: ", cookie)
		err = ch.SecureCookie.Decode(cookieName, cookie, &value)
		if err == nil {
			valueStr := string(value)
			return valueStr, nil
		}
	}

	return "", err
}

// AppLayer function to configure public paths
func WithPublicPaths(config PublicPathConfig) AppLayer {
	return func(s *Server) {
		s.publicPaths = make(map[string]bool)

		// Add exact matches
		for _, path := range config.Exact {
			s.publicPaths[path] = true
		}

		// Store prefix matches with special suffix
		for _, prefix := range config.Prefix {
			s.publicPaths[prefix+"/*"] = true
		}
	}
}

func (s *Server) isPublicPath(path string) bool {
	// Check exact matches first
	if s.publicPaths[path] {
		return true
	}

	// Check prefix matches
	for storedPath := range s.publicPaths {
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

// Internal token generation using the provided secret
// func (s *Server) generateToken() (string, error) {
// 	if len(s.config.SecretKey) == 0 {
// 		return "", fmt.Errorf("server secret key not configured")
// 	}

// 	// Generate random bytes for the token
// 	tokenBytes := make([]byte, 32)
// 	if _, err := rand.Read(tokenBytes); err != nil {
// 		return "", fmt.Errorf("failed to generate token: %w", err)
// 	}

// 	// Create HMAC for token verification
// 	h := hmac.New(sha256.New, s.config.SecretKey)
// 	h.Write(tokenBytes)
// 	signature := h.Sum(nil)

// 	// Combine token and signature
// 	final := append(tokenBytes, signature...)
// 	return base64.URLEncoding.EncodeToString(final), nil
// }

// Internal token validation
// func (s *Server) validateToken(token string) (bool, error) {
// 	// Decode token
// 	decoded, err := base64.URLEncoding.DecodeString(token)
// 	if err != nil {
// 		return false, fmt.Errorf("invalid token format")
// 	}

// 	if len(decoded) < 64 { // 32 bytes random + 32 bytes HMAC
// 		return false, fmt.Errorf("token too short")
// 	}

// 	// Split token and signature
// 	tokenBytes := decoded[:32]
// 	receivedSig := decoded[32:]

// 	// Verify HMAC
// 	h := hmac.New(sha256.New, s.config.SecretKey)
// 	h.Write(tokenBytes)
// 	expectedSig := h.Sum(nil)

// 	return hmac.Equal(receivedSig, expectedSig), nil
// }
