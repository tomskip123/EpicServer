package render

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
)

// RenderMode controls how the view renders with respect to HTMX.
type RenderMode int

const (
	RenderAuto    RenderMode = iota // partial when HX-Request and not boosted; else full
	RenderFull                      // always render full layout
	RenderPartial                   // always render only the content block
)

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

// HXRedirect asks htmx to redirect the browser to url.
func HXRedirect(w http.ResponseWriter, url string) { w.Header().Set("HX-Redirect", url) }

// HXLocation tells htmx to load a new URL (can be JSON config; here string or object).
func HXLocation(w http.ResponseWriter, req any) {
	switch t := req.(type) {
	case string:
		w.Header().Set("HX-Location", t)
	default:
		if b, err := json.Marshal(req); err == nil {
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

func setHXTriggerHeader(w http.ResponseWriter, key string, req any) {
	switch t := req.(type) {
	case string:
		w.Header().Set(key, t)
	case []string:
		if b, err := json.Marshal(t); err == nil {
			w.Header().Set(key, string(b))
		}
	case map[string]any:
		if b, err := json.Marshal(t); err == nil {
			w.Header().Set(key, string(b))
		}
	default:
		if b, err := json.Marshal(req); err == nil {
			w.Header().Set(key, string(b))
		}
	}
}

func (r *Renderer) injectHX(data any, req *http.Request) any {
	hx := HTMXFromRequest(req)
	if injectHXIntoMap(data, hx) {
		return data
	}
	return data
}

func injectHXIntoMap(data any, hx HTMX) bool {
	if data == nil {
		return false
	}
	v := reflect.ValueOf(data)
	if v.Kind() != reflect.Map || v.IsNil() {
		return false
	}
	if v.Type().Key().Kind() != reflect.String {
		return false
	}
	key := reflect.ValueOf("HX")
	if v.MapIndex(key).IsValid() {
		return true
	}

	elemType := v.Type().Elem()
	hxVal := reflect.ValueOf(hx)
	switch {
	case hxVal.Type().AssignableTo(elemType):
		v.SetMapIndex(key, hxVal)
		return true
	case elemType.Kind() == reflect.Interface:
		v.SetMapIndex(key, hxVal)
		return true
	default:
		return false
	}
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
