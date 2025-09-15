package epicserver

import (
	"errors"
	"net/http"
	"path"
	"sort"
	"strings"
)

// similar to view, follows a simpler approach.
type RouteBuilder struct {
	mux        *http.ServeMux
	base       string
	middleware []Middleware
	routes     map[string]map[string]http.Handler
}

func newRouteBuilder(mux *http.ServeMux, mw []Middleware) *RouteBuilder {
	return &RouteBuilder{
		mux:        mux,
		middleware: append([]Middleware(nil), mw...),
		routes:     make(map[string]map[string]http.Handler),
	}
}

func (r *RouteBuilder) Use(mw ...Middleware) *RouteBuilder {
	r.middleware = append(r.middleware, mw...)
	return r
}

func (r *RouteBuilder) Group(prefix string, fn func(*RouteBuilder)) *RouteBuilder {
	child := *r
	if prefix == "" {
		fn(&child)
		return r
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	child.base = path.Clean(path.Join("/", r.base, prefix))
	if child.base == "." {
		child.base = "/"
	}
	fn(&child)
	return r
}

func (r *RouteBuilder) Get(p string, h http.HandlerFunc) *RouteBuilder {
	return r.on(http.MethodGet, p, h)
}
func (r *RouteBuilder) Post(p string, h http.HandlerFunc) *RouteBuilder {
	return r.on(http.MethodPost, p, h)
}
func (r *RouteBuilder) Put(p string, h http.HandlerFunc) *RouteBuilder {
	return r.on(http.MethodPut, p, h)
}
func (r *RouteBuilder) Patch(p string, h http.HandlerFunc) *RouteBuilder {
	return r.on(http.MethodPatch, p, h)
}
func (r *RouteBuilder) Delete(p string, h http.HandlerFunc) *RouteBuilder {
	return r.on(http.MethodDelete, p, h)
}
func (r *RouteBuilder) Any(p string, h http.HandlerFunc) *RouteBuilder {
	return r.
		on(http.MethodGet, p, h).
		on(http.MethodPost, p, h).
		on(http.MethodPut, p, h).
		on(http.MethodPatch, p, h).
		on(http.MethodDelete, p, h).
		on(http.MethodOptions, p, h).
		on(http.MethodHead, p, h)
}

func (r *RouteBuilder) on(method, p string, h http.HandlerFunc) *RouteBuilder {
	full := r.join(r.base, p)
	if _, ok := r.routes[full]; !ok {
		r.routes[full] = make(map[string]http.Handler)
	}
	if _, exists := r.routes[full][method]; exists {
		// record duplicates; handled in apply()
		r.routes[full][method] = duplicateHandler()
		return r
	}
	r.routes[full][method] = http.HandlerFunc(h)
	return r
}

func (r *RouteBuilder) apply() error {
	var errs []error
	for p, methods := range r.routes {
		// detect duplicates flagged above
		for m, h := range methods {
			if h == duplicateHandler() {
				errs = append(errs, errors.New("duplicate route "+m+" "+p))
			}
		}
		// snapshot allowed methods for header
		allow := make([]string, 0, len(methods))
		for m := range methods {
			allow = append(allow, m)
		}
		sort.Strings(allow)
		allowHeader := strings.Join(allow, ", ")

		// wrap final dispatcher with middleware
		dispatcher := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if h, ok := methods[req.Method]; ok {
				r.wrap(h).ServeHTTP(w, req)
				return
			}
			w.Header().Set("Allow", allowHeader)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		})

		r.mux.Handle(p, dispatcher)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (r *RouteBuilder) wrap(next http.Handler) http.Handler {
	// If Middleware is a function type: func(http.Handler) http.Handler
	// fold from right to left
	for i := len(r.middleware) - 1; i >= 0; i-- {
		next = r.middleware[i](next)
	}
	return next
}

func (r *RouteBuilder) join(base, p string) string {
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if base == "" || base == "/" {
		return path.Clean(p)
	}
	return path.Clean(path.Join("/", base, p))
}

// sentinel for duplicate detection
type dupMarker struct{}

func (dupMarker) ServeHTTP(http.ResponseWriter, *http.Request) {}

func duplicateHandler() http.Handler { // comparable, safe to compare in apply()
	return dupMarker{}
}
