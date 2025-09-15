package epicserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// View renders Go html/templates with HTMX-aware behavior.
//
// Convention:
//   - Root: BaseDir (default "templates")
//   - Layouts: BaseDir/layouts/*.html. Expected to define a main template named "base"
//     using Go's block/define pattern, e.g.:
//     {{define "base"}}
//     <html>
//     <head>
//     {{block "head" .}}{{end}}
//     </head>
//     <body>
//     {{block "content" .}}{{end}}
//     {{block "scripts" .}}{{end}}
//     </body>
//     </html>
//     {{end}}
//   - Components: BaseDir/components/*.html. Each should {{define "components/name"}} ... {{end}}
//   - Pages: BaseDir/pages/*.html. Each should at least {{define "content"}} ... {{end}}
//
// Rendering:
// - Full page (non-HTMX or boosted HTMX): executes template named LayoutName (default "base").
// - Partial (HTMX request and not boosted): executes template named "content".
//
// In dev mode (Dev=true) templates reload on every render. In prod mode they are cached.
type View struct {
	// HTTP integration (optional, for convenient mounting)
	mux        *http.ServeMux
	middleware []Middleware

	// Templating configuration
	BaseDir       string
	PagesDir      string
	LayoutsDir    string
	ComponentsDir string
	LazyDir       string
	Ext           string // template file extension (default .html)
	LayoutName    string // main layout to Execute (default "base")
	Funcs         template.FuncMap
	Dev           bool

	// internal cache
	mu        sync.RWMutex
	shared    *template.Template            // layouts + components
	pageCache map[string]*template.Template // page name -> compiled set (shared+page)
}

// ViewOption configures a View.
type ViewOption func(*View)

// WithDev toggles dev mode (reload templates on each render).
func WithDev(dev bool) ViewOption { return func(v *View) { v.Dev = dev } }

// WithBaseDir sets the template base directory (default "templates").
func WithBaseDir(dir string) ViewOption { return func(v *View) { v.BaseDir = dir } }

// WithLayoutName sets the layout template name to execute for full page renders.
func WithLayoutName(name string) ViewOption { return func(v *View) { v.LayoutName = name } }

// WithFuncs adds template functions.
func WithFuncs(fn template.FuncMap) ViewOption {
	return func(v *View) {
		if v.Funcs == nil {
			v.Funcs = template.FuncMap{}
		}
		for k, f := range fn {
			v.Funcs[k] = f
		}
	}
}

// NewView creates a View bound to an optional mux and middleware chain.
// If mux is nil, you can still use v.Render and v.Handler to get handlers for registration elsewhere.
func NewView(mux *http.ServeMux, mw []Middleware, opts ...ViewOption) *View {
	v := &View{
		mux:           mux,
		middleware:    append([]Middleware(nil), mw...),
		BaseDir:       "templates",
		PagesDir:      "pages",
		LayoutsDir:    "layouts",
		ComponentsDir: "components",
		LazyDir:       "lazy",
		Ext:           ".html",
		LayoutName:    "base",
		Funcs:         template.FuncMap{},
		Dev:           false,
		pageCache:     make(map[string]*template.Template),
	}
	// default helpers
	v.addDefaultFuncs()
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Use appends per-view middleware applied to handlers created by this View.
func (v *View) Use(mw ...Middleware) *View {
	v.middleware = append(v.middleware, mw...)
	return v
}

// addDefaultFuncs registers common helpers used in templates.
func (v *View) addDefaultFuncs() {
	// concat: join strings together
	v.Funcs["concat"] = func(args ...any) string {
		var b strings.Builder
		for _, a := range args {
			b.WriteString(toString(a))
		}
		return b.String()
	}
	// attr: render key/value HTML attribute pairs from a map[string]string or map[string]any
	v.Funcs["attr"] = func(m any) template.HTML {
		switch t := m.(type) {
		case map[string]string:
			var b strings.Builder
			for k, val := range t {
				if val == "" { // boolean attribute when empty (omit)
					continue
				}
				b.WriteByte(' ')
				b.WriteString(template.HTMLEscapeString(k))
				b.WriteString("=\"")
				template.HTMLEscape(&b, []byte(val))
				b.WriteString("\"")
			}
			return template.HTML(b.String())
		case map[string]any:
			var b strings.Builder
			for k, v := range t {
				if v == nil {
					continue
				}
				s := toString(v)
				if s == "" {
					continue
				}
				b.WriteByte(' ')
				b.WriteString(template.HTMLEscapeString(k))
				b.WriteString("=\"")
				template.HTMLEscape(&b, []byte(s))
				b.WriteString("\"")
			}
			return template.HTML(b.String())
		default:
			return ""
		}
	}
	// partial: render a named template to a safe HTML string
	v.Funcs["partial"] = func(name string, data any) (template.HTML, error) {
		v.mu.RLock()
		t := v.shared
		v.mu.RUnlock()
		if t == nil {
			return "", errors.New("view: templates not loaded")
		}
		if t.Lookup(name) == nil {
			return "", errors.New("view: missing partial: " + name)
		}
		var buf bytes.Buffer
		if err := t.ExecuteTemplate(&buf, name, data); err != nil {
			return "", err
		}
		return template.HTML(buf.String()), nil
	}
}

// Build or refresh the shared template set (layouts + components).
func (v *View) loadShared() error {
	root := template.New("root").Funcs(v.Funcs)
	var files []string
	// collect layouts and components
	for _, dir := range []string{v.LayoutsDir, v.ComponentsDir} {
		base := filepath.Join(v.BaseDir, dir)
		_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // skip errors during walk; handled on parse
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Ext(path) != v.Ext {
				return nil
			}
			files = append(files, path)
			return nil
		})
	}
	if len(files) == 0 {
		// Allow using only page templates without shared parts, but keep an empty root
		v.mu.Lock()
		v.shared = root
		v.pageCache = map[string]*template.Template{}
		v.mu.Unlock()
		return nil
	}
	t, err := root.ParseFiles(files...)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.shared = t
	v.pageCache = map[string]*template.Template{} // reset cache on reload
	v.mu.Unlock()
	return nil
}

// resolvePagePath returns the filesystem path for a page name.
// Examples:
//
//	name "home"   -> BaseDir/pages/home.html
//	name "admin/users/index" -> BaseDir/pages/admin/users/index.html
//	name already ends with Ext -> used as-is if absolute or joined under BaseDir
func (v *View) resolvePagePath(name string) string {
	if strings.HasSuffix(name, v.Ext) {
		// if relative, join to BaseDir
		if !filepath.IsAbs(name) {
			return filepath.Join(v.BaseDir, name)
		}
		return name
	}
	return filepath.Join(v.BaseDir, v.PagesDir, filepath.FromSlash(name)+v.Ext)
}

// cloneWithPage returns a compiled template set for the given page, using cache when enabled.
func (v *View) cloneWithPage(page string) (*template.Template, error) {
	pageKey := filepath.ToSlash(page)
	v.mu.RLock()
	if !v.Dev {
		if t, ok := v.pageCache[pageKey]; ok {
			v.mu.RUnlock()
			return t, nil
		}
	}
	shared := v.shared
	v.mu.RUnlock()
	if shared == nil || v.Dev {
		if err := v.loadShared(); err != nil {
			return nil, err
		}
		v.mu.RLock()
		shared = v.shared
		v.mu.RUnlock()
	}
	clone, err := shared.Clone()
	if err != nil {
		return nil, err
	}
	pagePath := v.resolvePagePath(page)
	if _, err := os.Stat(pagePath); err != nil {
		return nil, err
	}
	if _, err := clone.ParseFiles(pagePath); err != nil {
		return nil, err
	}
	if !v.Dev {
		v.mu.Lock()
		v.pageCache[pageKey] = clone
		v.mu.Unlock()
	}
	return clone, nil
}

func (v *View) resolveLazyPath(name string) string {
	if strings.HasSuffix(name, v.Ext) {
		if !filepath.IsAbs(name) {
			return filepath.Join(v.BaseDir, name)
		}
		return name
	}
	return filepath.Join(v.BaseDir, v.LazyDir, filepath.FromSlash(name)+v.Ext)
}

func (v *View) cloneWithLazy(name string) (*template.Template, error) {
	v.mu.RLock()
	shared := v.shared
	v.mu.RUnlock()
	if shared == nil || v.Dev {
		if err := v.loadShared(); err != nil {
			return nil, err
		}
		v.mu.RLock()
		shared = v.shared
		v.mu.RUnlock()
	}
	clone, err := shared.Clone()
	if err != nil {
		return nil, err
	}
	path := v.resolveLazyPath(name)
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	if _, err := clone.ParseFiles(path); err != nil {
		return nil, err
	}
	return clone, nil
}

// RenderMode controls how the view renders with respect to HTMX.
type RenderMode int

const (
	RenderAuto    RenderMode = iota // partial when HX-Request and not boosted; else full
	RenderFull                      // always render full layout
	RenderPartial                   // always render only the content block
)

// Render writes HTML to the response using either the layout or the content block
// depending on HTMX request semantics. Data can be any value. If Data is a map
// (H, Fields, or map[string]any), HTMX info is injected under key "HX" when absent.
func (v *View) Render(w http.ResponseWriter, r *http.Request, page string, data any, mode RenderMode) error {
	t, err := v.cloneWithPage(page)
	if err != nil {
		return err
	}
	// Inject HX info into map data for template convenience
	data = v.injectHX(data, r)

	// Choose render mode
	if mode == RenderAuto {
		if IsHTMX(r) && !IsHTMXBoosted(r) {
			mode = RenderPartial
		} else {
			mode = RenderFull
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if mode == RenderPartial {
		// Prefer explicit "content" block
		if t.Lookup("content") == nil {
			return errors.New("view: missing 'content' template block for page '" + page + "'")
		}
		return t.ExecuteTemplate(w, "content", data)
	}
	// Full
	name := v.LayoutName
	if name == "" {
		name = "base"
	}
	if t.Lookup(name) == nil {
		// Fallback: attempt to execute by layout file base name if present
		return errors.New("view: missing layout template '" + name + "'")
	}
	return t.ExecuteTemplate(w, name, data)
}

// Handler returns an http.Handler that renders the given page with an optional data function.
// The handler automatically chooses partial vs full based on HTMX.
func (v *View) Handler(page string, dataFn func(*http.Request) any) http.Handler {
	return v.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data any
		if dataFn != nil {
			data = dataFn(r)
		}
		if err := v.Render(w, r, page, data, RenderAuto); err != nil {
			_ = HTML(w, http.StatusInternalServerError, "template render error: "+template.HTMLEscapeString(err.Error()))
		}
	}))
}

// MountGet is a convenience to register a GET route on the View's mux.
func (v *View) MountGet(path string, page string, dataFn func(*http.Request) any) *View {
	if v.mux == nil {
		return v
	}
	h := v.Handler(page, dataFn)
	v.mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		h.ServeHTTP(w, r)
	}))
	return v
}

func (v *View) RenderLazyHTML(w http.ResponseWriter, r *http.Request, name string, data any) error {
	t, err := v.cloneWithLazy(name)
	if err != nil {
		return err
	}
	data = v.injectHX(data, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Execute template by base filename so lazy files can either be raw markup or wrap a define.
	return t.ExecuteTemplate(w, filepath.Base(name), data)
}

func (v *View) LazyHandler(name string, dataFn func(*http.Request) any) http.Handler {
	return v.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data any
		if dataFn != nil {
			data = dataFn(r)
		}
		if err := v.RenderLazyHTML(w, r, name, data); err != nil {
			_ = HTML(w, http.StatusInternalServerError,
				"lazy template error: "+template.HTMLEscapeString(err.Error()))
		}
	}))
}

func (v *View) LazyHandlerFunc(name string, dataFn func(*http.Request) any) http.HandlerFunc {
	h := v.LazyHandler(name, dataFn)
	return func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}
}

func (v *View) MountLazyHTML(route string, name string, dataFn func(*http.Request) any) *View {
	if v.mux == nil {
		return v
	}
	h := v.LazyHandler(name, dataFn)
	v.mux.Handle(route, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		h.ServeHTTP(w, r)
	}))
	return v
}

// wrap applies the View's middleware chain to the final handler.
func (v *View) wrap(next http.Handler) http.Handler {
	for i := len(v.middleware) - 1; i >= 0; i-- {
		next = v.middleware[i](next)
	}
	return next
}

// injectHX puts HTMX request info under key "HX" into map data types when absent.
func (v *View) injectHX(data any, r *http.Request) any {
	hx := HTMXFromRequest(r)
	switch m := data.(type) {
	case H:
		if _, ok := m["HX"]; !ok {
			m["HX"] = hx
		}
		return m
	case Fields:
		if _, ok := m["HX"]; !ok {
			m["HX"] = hx
		}
		return m
	case map[string]any:
		if _, ok := m["HX"]; !ok {
			m["HX"] = hx
		}
		return m
	default:
		return data
	}
}

// HTMX carries key request headers from htmx.
type HTMX struct {
	Request               bool
	Boosted               bool
	Target                string
	Trigger               string
	TriggerName           string
	Prompt                string
	CurrentURL            string
	HistoryRestoreRequest bool
}

// HTMXFromRequest extracts HTMX info from the request.
func HTMXFromRequest(r *http.Request) HTMX {
	return HTMX{
		Request:               strings.EqualFold(r.Header.Get("HX-Request"), "true"),
		Boosted:               strings.EqualFold(r.Header.Get("HX-Boosted"), "true"),
		Target:                r.Header.Get("HX-Target"),
		Trigger:               r.Header.Get("HX-Trigger"),
		TriggerName:           r.Header.Get("HX-Trigger-Name"),
		Prompt:                r.Header.Get("HX-Prompt"),
		CurrentURL:            r.Header.Get("HX-Current-URL"),
		HistoryRestoreRequest: strings.EqualFold(r.Header.Get("HX-History-Restore-Request"), "true"),
	}
}

// IsHTMX reports if the request was made by htmx.
func IsHTMX(r *http.Request) bool { return HTMXFromRequest(r).Request }

// IsHTMXBoosted reports if the request was an htmx-boosted navigation.
func IsHTMXBoosted(r *http.Request) bool { return HTMXFromRequest(r).Boosted }

// --- HTMX response helpers ---

// HXRedirect asks htmx to redirect the browser to url.
func HXRedirect(w http.ResponseWriter, url string) { w.Header().Set("HX-Redirect", url) }

// HXLocation tells htmx to load a new URL (can be JSON config; here string or object).
func HXLocation(w http.ResponseWriter, v any) {
	switch t := v.(type) {
	case string:
		w.Header().Set("HX-Location", t)
	default:
		if b, err := json.Marshal(v); err == nil {
			w.Header().Set("HX-Location", string(b))
		}
	}
}

// HXPushURL controls history push of the current URL.
func HXPushURL(w http.ResponseWriter, v any) { w.Header().Set("HX-Push-Url", toString(v)) }

// HXReplaceURL replaces the current history entry.
func HXReplaceURL(w http.ResponseWriter, v any) { w.Header().Set("HX-Replace-Url", toString(v)) }

// HXReswap sets swap strategy, e.g., "outerHTML".
func HXReswap(w http.ResponseWriter, strategy string) { w.Header().Set("HX-Reswap", strategy) }

// HXRetarget changes the swap target CSS selector.
func HXRetarget(w http.ResponseWriter, sel string) { w.Header().Set("HX-Retarget", sel) }

// HXTrigger triggers client-side events. Provide a single event name string or map[string]any.
func HXTrigger(w http.ResponseWriter, v any) { setHXTriggerHeader(w, "HX-Trigger", v) }

// HXTriggerAfterSwap triggers events after swap.
func HXTriggerAfterSwap(w http.ResponseWriter, v any) {
	setHXTriggerHeader(w, "HX-Trigger-After-Swap", v)
}

// HXTriggerAfterSettle triggers events after settle.
func HXTriggerAfterSettle(w http.ResponseWriter, v any) {
	setHXTriggerHeader(w, "HX-Trigger-After-Settle", v)
}

// HXRefresh asks htmx to refresh the page.
func HXRefresh(w http.ResponseWriter) { w.Header().Set("HX-Refresh", "true") }

func setHXTriggerHeader(w http.ResponseWriter, key string, v any) {
	switch t := v.(type) {
	case string:
		w.Header().Set(key, t)
	case []string:
		// join as JSON array of event names
		if b, err := json.Marshal(t); err == nil {
			w.Header().Set(key, string(b))
		}
	case map[string]any:
		if b, err := json.Marshal(t); err == nil {
			w.Header().Set(key, string(b))
		}
	default:
		if b, err := json.Marshal(v); err == nil {
			w.Header().Set(key, string(b))
		}
	}
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		return strings.TrimSpace(strings.ReplaceAll(fmtAny(t), "\n", " "))
	}
}

func fmtAny(v any) string {
	// avoid importing fmt just for Sprintf; minimal reflection-based stringification
	// fall back to JSON when possible for complex types
	if b, err := json.Marshal(v); err == nil {
		return string(b)
	}
	return ""
}

// helper method to wrap Handler as HandlerFunc for compatibility with routes.go
func (v *View) HandlerFunc(page string, dataFn func(*http.Request) any) http.HandlerFunc {
	h := v.Handler(page, dataFn)
	return func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}
}
