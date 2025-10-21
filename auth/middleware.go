package auth

import (
	"context"
	"net/http"
)

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

type sessionContextKey struct{}
