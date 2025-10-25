package epicserver

import (
	"net/http"

	authpkg "github.com/tomskip123/EpicServer/auth"
)

// Middleware composes an http.Handler.
type Middleware = authpkg.Middleware

// Chain applies middlewares in order so mws[0] is outermost.
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		if mws[i] != nil {
			h = mws[i](h)
		}
	}
	return h
}

// CombineMiddleware collapses middlewares into a single middleware wrapper.
func CombineMiddleware(mws ...Middleware) Middleware {
	filtered := make([]Middleware, 0, len(mws))
	for _, mw := range mws {
		if mw != nil {
			filtered = append(filtered, mw)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return func(next http.Handler) http.Handler {
		for i := len(filtered) - 1; i >= 0; i-- {
			next = filtered[i](next)
		}
		return next
	}
}
