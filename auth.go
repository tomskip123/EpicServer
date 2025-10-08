package epicserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"
)

// AuthOption configures AuthModule.
type AuthOption func(*AuthModule)

// wellKnownProviderEndpoints covers common OAuth providers for quick setup.
var wellKnownProviderEndpoints = map[string]oauth2.Endpoint{
	"github": {
		AuthURL:  "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token",
	},
	"gitlab": {
		AuthURL:  "https://gitlab.com/oauth/authorize",
		TokenURL: "https://gitlab.com/oauth/token",
	},
	"google": {
		AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
	},
	"microsoft": {
		AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
	},
}

var wellKnownProviderScopes = map[string][]string{
	"github":    {"read:user", "user:email"},
	"gitlab":    {"read_user"},
	"google":    {"openid", "profile", "email"},
	"microsoft": {"openid", "profile", "email"},
}

var userInfoEndpoints = map[string]string{
	"google": "https://www.googleapis.com/oauth2/v3/userinfo",
}

// AuthConfigFromEnv builds an oauth2.Config using environment variables.
// Required variables (with prefix, default EPIC_AUTH):
//   - <PREFIX>_CLIENT_ID
//   - <PREFIX>_CLIENT_SECRET
//
// And either:
//   - <PREFIX>_PROVIDER (github, gitlab, google, microsoft)
//   - or <PREFIX>_AUTH_URL and <PREFIX>_TOKEN_URL
//
// Optional variables:
//   - <PREFIX>_REDIRECT_URL
//   - <PREFIX>_SCOPES (comma or space separated)
func AuthConfigFromEnv(prefix string) (*oauth2.Config, error) {
	if prefix == "" {
		prefix = "EPIC_AUTH"
	}
	prefix = strings.TrimSuffix(prefix, "_")
	prefix = strings.ToUpper(prefix)

	lookupRequired := func(suffix string) (string, error) {
		value, ok := os.LookupEnv(prefix + "_" + suffix)
		if !ok {
			return "", fmt.Errorf("%s_%s is required", prefix, suffix)
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return "", fmt.Errorf("%s_%s is required", prefix, suffix)
		}
		return value, nil
	}

	lookupOptional := func(suffix string) string {
		value, ok := os.LookupEnv(prefix + "_" + suffix)
		if !ok {
			return ""
		}
		return strings.TrimSpace(value)
	}

	clientID, err := lookupRequired("CLIENT_ID")
	if err != nil {
		return nil, err
	}
	clientSecret, err := lookupRequired("CLIENT_SECRET")
	if err != nil {
		return nil, err
	}

	authURL := lookupOptional("AUTH_URL")
	tokenURL := lookupOptional("TOKEN_URL")
	provider := strings.ToLower(lookupOptional("PROVIDER"))
	resolvedProvider := ""

	var endpoint oauth2.Endpoint
	switch {
	case authURL != "" || tokenURL != "":
		if authURL == "" || tokenURL == "" {
			return nil, fmt.Errorf("%s_AUTH_URL and %s_TOKEN_URL must both be set", prefix, prefix)
		}
		endpoint = oauth2.Endpoint{AuthURL: authURL, TokenURL: tokenURL}
	case provider != "":
		ep, ok := wellKnownProviderEndpoints[provider]
		if !ok {
			return nil, fmt.Errorf("unknown auth provider %q", provider)
		}
		resolvedProvider = provider
		endpoint = ep
	default:
		return nil, fmt.Errorf("set %s_PROVIDER or provide both %s_AUTH_URL and %s_TOKEN_URL", prefix, prefix, prefix)
	}

	redirectURL := lookupOptional("REDIRECT_URL")
	scopesValue := lookupOptional("SCOPES")
	if scopesValue != "" {
		scopesValue = strings.ReplaceAll(scopesValue, ",", " ")
	}
	scopes := strings.Fields(scopesValue)
	if len(scopes) == 0 && resolvedProvider != "" {
		if defaults, ok := wellKnownProviderScopes[resolvedProvider]; ok {
			scopes = append([]string(nil), defaults...)
		}
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     endpoint,
		Scopes:       scopes,
	}
	if redirectURL != "" {
		config.RedirectURL = redirectURL
	}

	return config, nil
}

// AuthModule manages OAuth login flows and cookie-backed sessions.
type AuthModule struct {
	mux        chi.Router
	middleware []Middleware
	App        *EZApp

	config *oauth2.Config

	loginPath    string
	callbackPath string
	logoutPath   string

	loginRedirectURL   string
	logoutRedirectURL  string
	failureRedirectURL string

	cookieName     string
	cookiePath     string
	cookieDomain   string
	cookieSecure   bool
	cookieHTTPOnly bool
	cookieSameSite http.SameSite

	sessionTTL time.Duration
	stateTTL   time.Duration

	sessions *sessionStore
	states   *stateStore
	now      func() time.Time
}

func newAuthModule(mux chi.Router, mw []Middleware, config *oauth2.Config, app *EZApp, opts ...AuthOption) *AuthModule {
	module := &AuthModule{
		mux:        mux,
		middleware: append([]Middleware(nil), mw...),
		config:     config,
		App:        app,

		loginPath:    "/auth/login",
		callbackPath: "/auth/callback",
		logoutPath:   "/auth/logout",

		loginRedirectURL:   "/",
		logoutRedirectURL:  "/",
		failureRedirectURL: "",

		cookieName:     "epic_session",
		cookiePath:     "/",
		cookieSecure:   true,
		cookieHTTPOnly: true,
		cookieSameSite: http.SameSiteLaxMode,

		sessionTTL: 24 * time.Hour,
		stateTTL:   5 * time.Minute,

		sessions: newSessionStore(),
		states:   newStateStore(),
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(module)
	}
	module.mountHandlers()
	return module
}

// SessionMiddleware enforces a valid session cookie and loads the session into the request context.
func (a *AuthModule) SessionMiddleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionID, ok := a.readSessionID(r)
			if !ok {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			session, ok := a.sessions.Get(sessionID, a.now())
			if !ok {
				a.clearSessionCookie(w)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SessionLoaderMiddleware populates the session in the request context if present without enforcing authentication.
func (a *AuthModule) SessionLoaderMiddleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionID, ok := a.readSessionID(r)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			session, ok := a.sessions.Get(sessionID, a.now())
			if !ok {
				a.clearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SessionFromContext retrieves the current session from ctx if present.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	session, ok := ctx.Value(sessionContextKey{}).(*Session)
	return session, ok
}

func (a *AuthModule) mountHandlers() {
	a.loginPath = sanitizePath(a.loginPath)
	a.callbackPath = sanitizePath(a.callbackPath)
	a.logoutPath = sanitizePath(a.logoutPath)

	a.mux.Handle(a.loginPath, a.wrap(http.HandlerFunc(a.handleLogin)))
	a.mux.Handle(a.callbackPath, a.wrap(http.HandlerFunc(a.handleCallback)))
	a.mux.Handle(a.logoutPath, a.wrap(http.HandlerFunc(a.handleLogout)))
}

func (a *AuthModule) handleLogin(w http.ResponseWriter, r *http.Request) {
	// if there is a next parameter in the url query, add that to state for callback to handle.
	next := r.URL.Query().Get("next")

	// then we set up a state store.
	state, err := a.states.New(a.stateTTL, a.now, next)
	if err != nil {
		http.Error(w, "failed to initiate oauth flow", http.StatusInternalServerError)
		return
	}

	redirectURL := a.config.RedirectURL
	if redirectURL == "" {
		redirectURL = a.resolveRedirectURL(r)
	}

	options := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	if redirectURL != "" {
		options = append(options, oauth2.SetAuthURLParam("redirect_uri", redirectURL))
	}

	authURL := a.config.AuthCodeURL(state, options...)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *AuthModule) handleCallback(w http.ResponseWriter, r *http.Request) {
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		a.fail(w, r, errors.New(errParam))
		return
	}

	state := r.URL.Query().Get("state")
	stateItem := a.states.Consume(state, a.now())
	if state == "" || stateItem == nil {
		a.fail(w, r, errors.New("invalid oauth state"))
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		a.fail(w, r, errors.New("missing oauth code"))
		return
	}

	redirectURL := a.config.RedirectURL
	if redirectURL == "" {
		redirectURL = a.resolveRedirectURL(r)
	}

	var exchangeOpts []oauth2.AuthCodeOption
	if redirectURL != "" {
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam("redirect_uri", redirectURL))
	}

	token, err := a.config.Exchange(r.Context(), code, exchangeOpts...)
	if err != nil {
		a.fail(w, r, err)
		return
	}

	session, err := a.sessions.Create(token, a.sessionTTL, a.now())
	if err != nil {
		a.fail(w, r, err)
		return
	}

	userInfo, err := a.GetUserInfo(r.Context(), token)
	if err != nil {
		a.App.Logger.Error.Fatal(err)
	}

	if a.App.User.IsEnabled() {
		_, err = a.App.User.RegisterUser(r.Context(), userInfo)
		if err != nil {
			a.App.Logger.Info.Println(err)
		}
	}

	// if redirect exists on the state item we redirect there instead.
	redirectPath := a.loginRedirectURL
	if stateItem.Redirect != "" {
		redirectPath = stateItem.Redirect
	}

	a.writeSessionCookie(w, session)
	a.redirect(w, r, redirectPath)
}

// getUserInfo is there to get user info from the oauth provider.
func (a *AuthModule) GetUserInfo(ctx context.Context, token *oauth2.Token) (*StatelessUser, error) {
	provider := strings.ToLower(strings.TrimSpace(a.App.Config.Auth.DefaultProvider))
	endpoint, ok := userInfoEndpoints[provider]
	if !ok {
		return nil, fmt.Errorf("no userinfo endpoint configured for provider %q", provider)
	}

	client := a.config.Client(ctx, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build userinfo request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch userinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("userinfo %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Subject string `json:"sub"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}

	return &StatelessUser{Name: payload.Name, Email: payload.Email, Picture: payload.Picture}, nil
}

func (a *AuthModule) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := a.readSessionID(r)
	if ok {
		a.sessions.Delete(sessionID)
	}
	a.clearSessionCookie(w)
	a.redirect(w, r, a.logoutRedirectURL)
}

func (a *AuthModule) redirect(w http.ResponseWriter, r *http.Request, url string) {
	if url == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func (a *AuthModule) fail(w http.ResponseWriter, r *http.Request, err error) {
	if a.failureRedirectURL != "" {
		http.Redirect(w, r, a.failureRedirectURL, http.StatusFound)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

func (a *AuthModule) resolveRedirectURL(r *http.Request) string {
	scheme := requestScheme(r)
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "localhost"
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, a.callbackPath)
}

func requestScheme(r *http.Request) string {
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if proto != "" {
		if idx := strings.IndexByte(proto, ','); idx >= 0 {
			proto = proto[:idx]
		}
		proto = strings.TrimSpace(proto)
		if proto != "" {
			return strings.ToLower(proto)
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func (a *AuthModule) wrap(next http.Handler) http.Handler {
	for i := len(a.middleware) - 1; i >= 0; i-- {
		next = a.middleware[i](next)
	}
	return next
}

func (a *AuthModule) readSessionID(r *http.Request) (string, bool) {
	c, err := r.Cookie(a.cookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

func (a *AuthModule) writeSessionCookie(w http.ResponseWriter, session *Session) {
	maxAge := int(time.Until(session.ExpiresAt).Seconds())
	if maxAge <= 0 {
		maxAge = int(a.sessionTTL.Seconds())
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    session.ID,
		Path:     a.cookiePath,
		Domain:   a.cookieDomain,
		Secure:   a.cookieSecure,
		HttpOnly: a.cookieHTTPOnly,
		SameSite: a.cookieSameSite,
		Expires:  session.ExpiresAt,
		MaxAge:   maxAge,
	})
}

func (a *AuthModule) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    "",
		Path:     a.cookiePath,
		Domain:   a.cookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   a.cookieSecure,
		HttpOnly: a.cookieHTTPOnly,
		SameSite: a.cookieSameSite,
	})
}

// WithAuthMiddleware appends middleware to the auth handlers.
func WithAuthMiddleware(mw ...Middleware) AuthOption {
	return func(a *AuthModule) {
		if len(mw) > 0 {
			a.middleware = append(a.middleware, mw...)
		}
	}
}

// WithSessionCookieName overrides the default session cookie name.
func WithSessionCookieName(name string) AuthOption {
	return func(a *AuthModule) {
		if name != "" {
			a.cookieName = name
		}
	}
}

// WithCookieDomain sets the cookie domain attribute.
func WithCookieDomain(domain string) AuthOption {
	return func(a *AuthModule) {
		a.cookieDomain = domain
	}
}

// WithCookiePath sets the cookie path attribute.
func WithCookiePath(p string) AuthOption {
	return func(a *AuthModule) {
		a.cookiePath = sanitizePath(p)
	}
}

// WithInsecureCookies disables the Secure flag, useful for local HTTP development.
func WithInsecureCookies() AuthOption {
	return func(a *AuthModule) {
		a.cookieSecure = false
	}
}

// WithCookieSameSite sets the SameSite attribute on the session cookie.
func WithCookieSameSite(mode http.SameSite) AuthOption {
	return func(a *AuthModule) {
		a.cookieSameSite = mode
	}
}

// WithSessionTTL overrides the default session lifetime.
func WithSessionTTL(ttl time.Duration) AuthOption {
	return func(a *AuthModule) {
		if ttl > 0 {
			a.sessionTTL = ttl
		}
	}
}

// WithStateTTL overrides how long OAuth state values remain valid.
func WithStateTTL(ttl time.Duration) AuthOption {
	return func(a *AuthModule) {
		if ttl > 0 {
			a.stateTTL = ttl
		}
	}
}

// WithLoginPath customizes the login endpoint path.
func WithLoginPath(p string) AuthOption {
	return func(a *AuthModule) {
		if p != "" {
			a.loginPath = p
		}
	}
}

// WithCallbackPath customizes the OAuth callback endpoint path.
func WithCallbackPath(p string) AuthOption {
	return func(a *AuthModule) {
		if p != "" {
			a.callbackPath = p
		}
	}
}

// WithLogoutPath customizes the logout endpoint path.
func WithLogoutPath(p string) AuthOption {
	return func(a *AuthModule) {
		if p != "" {
			a.logoutPath = p
		}
	}
}

// WithLoginRedirect sets where users go after completing the OAuth callback successfully.
func WithLoginRedirect(url string) AuthOption {
	return func(a *AuthModule) {
		a.loginRedirectURL = url
	}
}

// WithLogoutRedirect sets where users go after logging out.
func WithLogoutRedirect(url string) AuthOption {
	return func(a *AuthModule) {
		a.logoutRedirectURL = url
	}
}

// WithFailureRedirect sets where users are sent when the OAuth flow fails.
func WithFailureRedirect(url string) AuthOption {
	return func(a *AuthModule) {
		a.failureRedirectURL = url
	}
}

// WithClock allows tests to inject a deterministic clock.
func WithClock(now func() time.Time) AuthOption {
	return func(a *AuthModule) {
		if now != nil {
			a.now = now
		}
	}
}

type sessionContextKey struct{}

// Session represents the authenticated user session backed by an OAuth token.
type Session struct {
	ID        string
	Token     *oauth2.Token
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Valid reports whether the session is still active.
func (s *Session) Valid(now time.Time) bool {
	return now.Before(s.ExpiresAt)
}

type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]*Session)}
}

func (s *sessionStore) Create(token *oauth2.Token, ttl time.Duration, now time.Time) (*Session, error) {
	id, err := randomString(32)
	if err != nil {
		return nil, err
	}
	expiry := now.Add(ttl)
	if token != nil && !token.Expiry.IsZero() && token.Expiry.Before(expiry) {
		expiry = token.Expiry
	}
	session := &Session{
		ID:        id,
		Token:     token,
		CreatedAt: now,
		ExpiresAt: expiry,
	}
	s.mu.Lock()
	s.sessions[id] = session
	s.mu.Unlock()
	return session, nil
}

func (s *sessionStore) Get(id string, now time.Time) (*Session, bool) {
	s.mu.RLock()
	session, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if !session.Valid(now) {
		s.Delete(id)
		return nil, false
	}
	return session, true
}

func (s *sessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

type StateStoreItem struct {
	Expiry   time.Time
	Redirect string
}

// TODO: do we provide more options than just an in-memory store for temporarily storing
// state between auth2 redirects?
type stateStore struct {
	mu    sync.Mutex
	items map[string]StateStoreItem
}

func newStateStore() *stateStore {
	return &stateStore{items: make(map[string]StateStoreItem)}
}

// set a value based off a random string.
func (s *stateStore) New(ttl time.Duration, now func() time.Time, redirect string) (string, error) {
	value, err := randomString(32)
	if err != nil {
		return "", err
	}

	expires := now().Add(ttl)
	s.mu.Lock()

	s.items[value] = StateStoreItem{
		Expiry:   expires,
		Redirect: redirect,
	}

	s.mu.Unlock()
	return value, nil
}

// Once a value has been read, it is destroyed.
func (s *stateStore) Consume(value string, now time.Time) *StateStoreItem {
	s.mu.Lock()

	stateItem, ok := s.items[value]
	if ok {
		delete(s.items, value)
	}

	s.mu.Unlock()
	if !ok {
		return nil
	}

	return &stateItem
}

func randomString(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func sanitizePath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	cleaned := path.Clean(p)
	if cleaned == "." {
		return "/"
	}
	return cleaned
}
