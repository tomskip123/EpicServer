package epicserver

import (
	"errors"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/tomskip123/EpicServer/config"
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
	mux        chi.Router
	base       string
	middleware []Middleware
	Logger     *Logger
	Config     *config.Config
}

func newRouteBuilder(mux chi.Router, mw []Middleware, logger *Logger, cfg *config.Config) *RouteBuilder {
	return &RouteBuilder{
		mux:        mux,
		middleware: append([]Middleware(nil), mw...),
		Logger:     logger,
		Config:     cfg,
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
	r.Logger.Info.Printf("Route: method=%s, path=%s", method, p)

	full := r.join(r.base, p)
	if _, ok := routeRegistry[full]; !ok {
		routeRegistry[full] = &RouteSpec{
			Name:    full,
			Path:    full,
			Methods: make(map[string]http.Handler),
		}
	}

	if _, ok := routeRegistry[full].Methods[method]; ok {
		r.Logger.Info.Printf("exists = %v", ok)
		routeRegistry[full].Methods[method] = duplicateHandler()
		return r
	}

	routeRegistry[full].Methods[method] = http.HandlerFunc(h)
	return r
}

// Apply loops through r.routes recorded in on() and registers them with chi.
// It also wraps them with the middleware stack and sets up method dispatching.
// If duplicates were detected, it returns an error listing them.
func (r *RouteBuilder) apply() error {
	var errs []error

	// detect duplicates flagged above
	for p, spec := range routeRegistry {
		for m, h := range spec.Methods {
			if h == duplicateHandler() {
				errs = append(errs, errors.New("duplicate route "+m+" "+p))
			}
		}
	}

	// Precompute Allow header per chi pattern so we can set it in MethodNotAllowed
	allowByPattern := make(map[string]string)

	for p, spec := range routeRegistry {
		chiPattern := toChiPattern(p)

		// compute Allow
		allow := make([]string, 0, len(spec.Methods))
		for m := range spec.Methods {
			allow = append(allow, m)
		}
		sort.Strings(allow)
		allowHeader := strings.Join(allow, ", ")
		allowByPattern[chiPattern] = allowHeader

		// register each method for this pattern
		for m, h := range spec.Methods {
			if h == duplicateHandler() {
				continue
			}
			r.mux.Method(m, chiPattern, r.wrap(h))
		}
	}

	// Global 404 and 405 (run through middleware)
	{
		wrapped := r.wrap(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.NotFound(w, req)
		}))
		r.mux.NotFound(func(w http.ResponseWriter, req *http.Request) {
			wrapped.ServeHTTP(w, req)
		})
	}
	{
		wrapped := r.wrap(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Try to set per-route Allow header
			if rctx := chi.RouteContext(req.Context()); rctx != nil {
				if pat := rctx.RoutePattern(); pat != "" {
					if allow := allowByPattern[pat]; allow != "" {
						w.Header().Set("Allow", allow)
					}
				}
			}
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		}))
		r.mux.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
			wrapped.ServeHTTP(w, req)
		})
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// wrap applies the middleware stack to the given handler.
func (r *RouteBuilder) wrap(next http.Handler) http.Handler {
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

// Convert ":param" style to chi "{param}" style.
func toChiPattern(p string) string {
	clean := path.Clean(p)
	if clean == "" {
		return "/"
	}
	segs := strings.Split(clean, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") && len(s) > 1 {
			segs[i] = "{" + s[1:] + "}"
		}
	}
	res := strings.Join(segs, "/")
	if !strings.HasPrefix(res, "/") {
		res = "/" + res
	}
	return res
}

// sentinel for duplicate detection
type dupMarker struct{}

func (dupMarker) ServeHTTP(http.ResponseWriter, *http.Request) {}

func duplicateHandler() http.Handler { // comparable, safe to compare in apply()
	return dupMarker{}
}
