package render

import (
	"errors"
	"html/template"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
)

// Dependencies capture integration points with the hosting application.
type Dependencies struct {
	// Wrap applies middleware around a handler before exposure.
	Wrap func(http.Handler) http.Handler
	// MountGet registers a GET handler at the provided route.
	MountGet func(string, http.Handler)
}

// Renderer renders Go html/templates with HTMX-aware behavior.
//
// Convention:
//   - Root: BaseDir (default "templates")
//   - Layouts: BaseDir/layouts/*.html with a main template named "base".
//   - Components: BaseDir/components/*.html defining {{define "components/name"}}.
//   - Pages: BaseDir/pages/*.html defining at least {{define "content"}}.
//
// Rendering:
//   - Full page (non-HTMX or boosted HTMX): executes template named LayoutName (default "base").
//   - Partial (HTMX request and not boosted): executes template named "content".
//
// In dev mode (Dev=true) templates reload on every render. In prod mode they are cached.
type Renderer struct {
	BaseDir       string
	PagesDir      string
	LayoutsDir    string
	ComponentsDir string
	LazyDir       string
	Ext           string // template file extension (default .html)
	LayoutName    string // main layout to Execute (default "base")
	Funcs         template.FuncMap
	Dev           bool

	mu        sync.RWMutex
	shared    *template.Template
	pageCache map[string]*template.Template

	wrapFunc func(http.Handler) http.Handler
	mountGet func(string, http.Handler)
}

// ViewOption configures a Renderer.
type ViewOption func(*Renderer)

// ViewDataFunc prepares data for rendering. Return false to skip the default render
// when you already wrote to the ResponseWriter.
type ViewDataFunc func(http.ResponseWriter, *http.Request) (any, bool)

// NewRenderer creates a Renderer with the provided dependencies and options.
func NewRenderer(deps Dependencies, opts ...ViewOption) *Renderer {
	r := &Renderer{
		BaseDir:       "templates",
		PagesDir:      "pages",
		LayoutsDir:    "layouts",
		ComponentsDir: "components",
		LazyDir:       "lazy",
		Ext:           ".html",
		LayoutName:    "base",
		Funcs:         template.FuncMap{},
		pageCache:     make(map[string]*template.Template),
		wrapFunc:      deps.Wrap,
		mountGet:      deps.MountGet,
	}
	r.addDefaultFuncs()
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Render writes HTML to the response using either the layout or the content block
// depending on HTMX request semantics. Data can be any value. If Data is a map-like
// structure with string keys, HTMX info is injected under key "HX" when absent.
func (r *Renderer) Render(w http.ResponseWriter, req *http.Request, page string, data any, mode RenderMode) error {
	t, err := r.cloneWithPage(page)
	if err != nil {
		return err
	}
	// Inject HX info into map data for template convenience.
	data = r.injectHX(data, req)

	// Choose render mode.
	if mode == RenderAuto {
		if IsHTMX(req) && !IsHTMXBoosted(req) {
			mode = RenderPartial
		} else {
			mode = RenderFull
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if mode == RenderPartial {
		if t.Lookup("content") == nil {
			return errors.New("view: missing 'content' template block for page '" + page + "'")
		}
		return t.ExecuteTemplate(w, "content", data)
	}
	name := r.LayoutName
	if name == "" {
		name = "base"
	}
	if t.Lookup(name) == nil {
		return errors.New("view: missing layout template '" + name + "'")
	}
	return t.ExecuteTemplate(w, name, data)
}

// Handler returns an http.Handler that renders the given page with an optional data function.
// The handler automatically chooses partial vs full based on HTMX semantics.
func (r *Renderer) Handler(page string, dataFn ViewDataFunc) http.Handler {
	return r.wrap(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var (
			data any
			cont = true
		)
		if dataFn != nil {
			data, cont = dataFn(w, req)
		}
		if !cont {
			return
		}
		if err := r.Render(w, req, page, data, RenderAuto); err != nil {
			writeHTML(w, http.StatusInternalServerError,
				"template render error: "+template.HTMLEscapeString(err.Error()))
		}
	}))
}

// MountGet is a convenience to register a GET route with the Renderer.
func (r *Renderer) MountGet(route string, page string, dataFn ViewDataFunc) *Renderer {
	if r.mountGet == nil {
		return r
	}
	normalized := route
	if normalized == "" {
		normalized = "/"
	}
	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}
	if strings.HasSuffix(normalized, "/") && normalized != "/" {
		normalized = strings.TrimSuffix(normalized, "/")
	}
	wrappedFn := dataFn
	if normalized == "/" {
		wrappedFn = func(w http.ResponseWriter, req *http.Request) (any, bool) {
			if req.URL.Path != "/" {
				if dataFn != nil {
					if _, cont := dataFn(w, req); !cont {
						return nil, false
					}
				}
				http.NotFound(w, req)
				return nil, false
			}
			if dataFn != nil {
				return dataFn(w, req)
			}
			return nil, true
		}
	}

	h := r.Handler(page, wrappedFn)
	r.mountGet(normalized, h)

	return r
}

// HandlerFunc wraps Handler for compatibility with interfaces needing http.HandlerFunc.
func (r *Renderer) HandlerFunc(page string, dataFn ViewDataFunc) http.HandlerFunc {
	h := r.Handler(page, dataFn)
	return func(w http.ResponseWriter, req *http.Request) {
		h.ServeHTTP(w, req)
	}
}

func (r *Renderer) wrap(next http.Handler) http.Handler {
	if r.wrapFunc == nil {
		return next
	}
	return r.wrapFunc(next)
}

func (r *Renderer) resolvePagePath(name string) string {
	if strings.HasSuffix(name, r.Ext) {
		if !filepath.IsAbs(name) {
			return filepath.Join(r.BaseDir, name)
		}
		return name
	}
	return filepath.Join(r.BaseDir, r.PagesDir, filepath.FromSlash(name)+r.Ext)
}

func (r *Renderer) resolveLazyPath(name string) string {
	if strings.HasSuffix(name, r.Ext) {
		if !filepath.IsAbs(name) {
			return filepath.Join(r.BaseDir, name)
		}
		return name
	}
	return filepath.Join(r.BaseDir, r.LazyDir, filepath.FromSlash(name)+r.Ext)
}
