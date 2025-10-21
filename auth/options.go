package auth

import (
	"net/http"
	"time"
)

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
		a.loginPath = sanitizePath(p)
	}
}

// WithCallbackPath customizes the OAuth callback endpoint path.
func WithCallbackPath(p string) AuthOption {
	return func(a *AuthModule) {
		a.callbackPath = sanitizePath(p)
	}
}

// WithLogoutPath customizes the logout endpoint path.
func WithLogoutPath(p string) AuthOption {
	return func(a *AuthModule) {
		a.logoutPath = sanitizePath(p)
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
