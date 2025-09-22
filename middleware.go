package epicserver

import "net/http"

// Middleware composes an http.Handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middlewares in order so mws[0] is outermost.
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		if mws[i] != nil {
			h = mws[i](h)
		}
	}
	return h
}
