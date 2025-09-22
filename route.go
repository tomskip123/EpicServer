package epicserver

import (
	"errors"
	"log"
	"net/http"
	"path"
	"sort"
	"strings"
)

type Route = http.Handler

type RouteSpec struct {
	Name    string
	Path    string
	Methods map[string]Route
}

var routeRegistry = make(map[string]*RouteSpec)

// similar to view, follows a simpler approach.
type RouteBuilder struct {
	mux        *http.ServeMux
	base       string
	middleware []Middleware
}

func newRouteBuilder(mux *http.ServeMux, mw []Middleware) *RouteBuilder {
	return &RouteBuilder{
		mux:        mux,
		middleware: append([]Middleware(nil), mw...),
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

func (r *RouteBuilder) Get(p string, h Route) *RouteBuilder {
	return r.on(http.MethodGet, p, http.HandlerFunc(h.ServeHTTP))
}
func (r *RouteBuilder) Post(p string, h Route) *RouteBuilder {
	return r.on(http.MethodPost, p, http.HandlerFunc(h.ServeHTTP))
}
func (r *RouteBuilder) Put(p string, h Route) *RouteBuilder {
	return r.on(http.MethodPut, p, http.HandlerFunc(h.ServeHTTP))
}
func (r *RouteBuilder) Patch(p string, h Route) *RouteBuilder {
	return r.on(http.MethodPatch, p, http.HandlerFunc(h.ServeHTTP))
}
func (r *RouteBuilder) Delete(p string, h Route) *RouteBuilder {
	return r.on(http.MethodDelete, p, http.HandlerFunc(h.ServeHTTP))
}
func (r *RouteBuilder) Any(p string, h Route) *RouteBuilder {
	return r.
		on(http.MethodGet, p, http.HandlerFunc(h.ServeHTTP)).
		on(http.MethodPost, p, http.HandlerFunc(h.ServeHTTP)).
		on(http.MethodPut, p, http.HandlerFunc(h.ServeHTTP)).
		on(http.MethodPatch, p, http.HandlerFunc(h.ServeHTTP)).
		on(http.MethodDelete, p, http.HandlerFunc(h.ServeHTTP)).
		on(http.MethodOptions, p, http.HandlerFunc(h.ServeHTTP)).
		on(http.MethodHead, p, http.HandlerFunc(h.ServeHTTP))
}

// on method registers the handler for the given method and path.
// It checks for duplicates and records them to be handled in apply().
func (r *RouteBuilder) on(method, p string, h http.HandlerFunc) *RouteBuilder {
	logger.Printf("Route registry: %v", routeRegistry)

	logger.Printf("Route structurer.on: method=%s, path=%s", method, p)

	full := r.join(r.base, p)
	if _, ok := routeRegistry[full]; !ok {
		routeRegistry[full] = &RouteSpec{
			Name:    full,
			Path:    full,
			Methods: make(map[string]http.Handler),
		}
	}

	if _, ok := routeRegistry[full].Methods[method]; ok {
		// duplicate route detected;
		logger.Printf("exists = %v", ok)
		// mark as duplicate
		// record duplicates; handled in apply()
		routeRegistry[full].Methods[method] = duplicateHandler()
		return r
	}

	routeRegistry[full].Methods[method] = http.HandlerFunc(h)
	return r
}

// Apply loops through r.routes recorded in on() and registers them with the mux.
// It also wraps them with the middleware stack and sets up method dispatching.
// If duplicates were detected, it returns an error listing them.
func (r *RouteBuilder) apply() error {
	var errs []error

	// hold root ("/") so we can wrap it specially
	var rootSpec *RouteSpec
	var rootAllowHeader string

	for p, routeSpec := range routeRegistry {
		// detect duplicates flagged above
		for m, h := range routeSpec.Methods {
			if h == duplicateHandler() {
				errs = append(errs, errors.New("duplicate route "+m+" "+p))
			}
		}
		// snapshot allowed methods for header
		allow := make([]string, 0, len(routeSpec.Methods))
		for m := range routeSpec.Methods {
			allow = append(allow, m)
		}
		sort.Strings(allow)
		allowHeader := strings.Join(allow, ", ")

		// wrap final dispatcher with middleware
		dispatcher := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			log.Println("Dispatching", req.Method, req.URL.Path)
			if h, ok := routeSpec.Methods[req.Method]; ok {
				r.wrap(h).ServeHTTP(w, req)
				return
			}
			w.Header().Set("Allow", allowHeader)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		})

		if p == "/" {
			// Defer registering "/" so we can inject 404 for non-root paths.
			rootSpec = routeSpec
			rootAllowHeader = allowHeader
			continue
		}

		r.mux.Handle(p, dispatcher)

	}

	// If "/" exists, wrap it so it only handles the exact "/" path.
	// For any other path that fell through to "/", return 404 (running middleware).
	if rootSpec != nil {
		r.mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if path.Clean(req.URL.Path) != "/" {
				// unmatched: run middleware chain and return 404
				r.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.NotFound(w, r)
				})).ServeHTTP(w, req)
				return
			}
			// exact "/" – do normal method dispatch
			if h, ok := rootSpec.Methods[req.Method]; ok {
				r.wrap(h).ServeHTTP(w, req)
				return
			}
			w.Header().Set("Allow", rootAllowHeader)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		}))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// wrap applies the middleware stack to the given handler.
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
