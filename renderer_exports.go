package epicserver

import (
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/tomskip123/EpicServer/render"
)

type (
	Renderer     = render.Renderer
	ViewOption   = render.ViewOption
	ViewDataFunc = render.ViewDataFunc
	RenderMode   = render.RenderMode
	HTMX         = render.HTMX
)

const (
	RenderAuto    = render.RenderAuto
	RenderFull    = render.RenderFull
	RenderPartial = render.RenderPartial
)

func WithDev(dev bool) ViewOption { return render.WithDev(dev) }

func WithBaseDir(dir string) ViewOption { return render.WithBaseDir(dir) }

func WithLayoutName(name string) ViewOption { return render.WithLayoutName(name) }

func WithFuncs(fn template.FuncMap) ViewOption { return render.WithFuncs(fn) }

func NewRenderer[T any](_ chi.Router, _ []Middleware, rb *RouteBuilderWith[T], _ *Logger, opts ...ViewOption) *Renderer {
	var deps render.Dependencies
	if rb != nil {
		deps.Wrap = rb.wrap
		deps.MountGet = func(route string, handler http.Handler) {
			rb.Get(route, handler)
		}
	}
	return render.NewRenderer(deps, opts...)
}

func HTMXFromRequest(r *http.Request) HTMX { return render.HTMXFromRequest(r) }

func IsHTMX(r *http.Request) bool { return render.IsHTMX(r) }

func IsHTMXBoosted(r *http.Request) bool { return render.IsHTMXBoosted(r) }

func HXRedirect(w http.ResponseWriter, url string) { render.HXRedirect(w, url) }

func HXLocation(w http.ResponseWriter, req any) { render.HXLocation(w, req) }

func HXPushURL(w http.ResponseWriter, v any) { render.HXPushURL(w, v) }

func HXReplaceURL(w http.ResponseWriter, v any) { render.HXReplaceURL(w, v) }

func HXReswap(w http.ResponseWriter, strategy string) { render.HXReswap(w, strategy) }

func HXRetarget(w http.ResponseWriter, sel string) { render.HXRetarget(w, sel) }

func HXTrigger(w http.ResponseWriter, v any) { render.HXTrigger(w, v) }

func HXTriggerAfterSwap(w http.ResponseWriter, v any) { render.HXTriggerAfterSwap(w, v) }

func HXTriggerAfterSettle(w http.ResponseWriter, v any) { render.HXTriggerAfterSettle(w, v) }

func HXRefresh(w http.ResponseWriter) { render.HXRefresh(w) }
