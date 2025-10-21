package render

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"maps"
	"strings"
)

// WithDev toggles dev mode (reload templates on each render).
func WithDev(dev bool) ViewOption { return func(r *Renderer) { r.Dev = dev } }

// WithBaseDir sets the template base directory (default "templates").
func WithBaseDir(dir string) ViewOption { return func(r *Renderer) { r.BaseDir = dir } }

// WithLayoutName sets the layout template name to execute for full page renders.
func WithLayoutName(name string) ViewOption { return func(r *Renderer) { r.LayoutName = name } }

// WithFuncs adds template functions.
func WithFuncs(fn template.FuncMap) ViewOption {
	return func(r *Renderer) {
		if r.Funcs == nil {
			r.Funcs = template.FuncMap{}
		}
		maps.Copy(r.Funcs, fn)
	}
}

func (r *Renderer) addDefaultFuncs() {
	r.Funcs["concat"] = func(args ...any) string {
		var b strings.Builder
		for _, a := range args {
			b.WriteString(toString(a))
		}
		return b.String()
	}
	r.Funcs["attr"] = func(m any) template.HTML {
		switch t := m.(type) {
		case map[string]string:
			var b strings.Builder
			for k, val := range t {
				if val == "" {
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
	r.Funcs["partial"] = func(name string, data any) (template.HTML, error) {
		r.mu.RLock()
		t := r.shared
		r.mu.RUnlock()
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

func toString(req any) string {
	switch t := req.(type) {
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
	if b, err := json.Marshal(v); err == nil {
		return string(b)
	}
	return ""
}
