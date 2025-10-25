package render

import (
	"html/template"
	"net/http"
	"path/filepath"
)

func (r *Renderer) RenderLazyHTML(w http.ResponseWriter, req *http.Request, name string, data any) error {
	t, err := r.cloneWithLazy(name)
	if err != nil {
		return err
	}
	hx := HTMXFromRequest(req)
	data = r.injectHX(data, hx)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	base := filepath.Base(name)
	root := filepath.Base(r.resolveLazyPath(name))

	if t.Lookup(base) != nil {
		return t.ExecuteTemplate(w, base, data)
	}
	return t.ExecuteTemplate(w, root, data)
}

func (r *Renderer) LazyHandler(name string, dataFn ViewDataFunc) http.Handler {
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
		if err := r.RenderLazyHTML(w, req, name, data); err != nil {
			writeHTML(w, http.StatusInternalServerError,
				"lazy template error: "+template.HTMLEscapeString(err.Error()))
		}
	}))
}
