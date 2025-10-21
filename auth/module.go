package auth

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"
)

// AuthModule manages OAuth login flows and cookie-backed sessions.
type AuthModule struct {
	mux        chi.Router
	middleware []Middleware

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

	loggers         Loggers
	user            UserRegistrar
	defaultProvider string
}

// New constructs an AuthModule with the provided dependencies.
func New(mux chi.Router, mw []Middleware, config *oauth2.Config, deps Dependencies, opts ...AuthOption) *AuthModule {
	module := &AuthModule{
		mux:        mux,
		middleware: append([]Middleware(nil), mw...),
		config:     config,

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

		loggers: Loggers{
			Error: deps.Loggers.Error,
			Info:  deps.Loggers.Info,
		},
		user:            deps.User,
		defaultProvider: deps.DefaultProvider,
	}
	for _, opt := range opts {
		opt(module)
	}
	module.mountHandlers()
	return module
}

func (a *AuthModule) mountHandlers() {
	a.loginPath = sanitizePath(a.loginPath)
	a.callbackPath = sanitizePath(a.callbackPath)
	a.logoutPath = sanitizePath(a.logoutPath)

	a.mux.Handle(a.loginPath, a.wrap(http.HandlerFunc(a.handleLogin)))
	a.mux.Handle(a.callbackPath, a.wrap(http.HandlerFunc(a.handleCallback)))
	a.mux.Handle(a.logoutPath, a.wrap(http.HandlerFunc(a.handleLogout)))
}

func (a *AuthModule) wrap(next http.Handler) http.Handler {
	for i := len(a.middleware) - 1; i >= 0; i-- {
		next = a.middleware[i](next)
	}
	return next
}
