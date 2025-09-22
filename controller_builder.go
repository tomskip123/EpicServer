package epicserver

import (
	"fmt"
	"net/http"
)

type ControllerBuilder interface {
	Register(name string, c Controller)
	Build(app EZApp) error
}

type controllerBuilder struct {
	controllers  map[string]Controller
	routeBuilder *RouteBuilder
}

func newControllerBuilder(rb *RouteBuilder) ControllerBuilder {
	return &controllerBuilder{
		controllers:  make(map[string]Controller),
		routeBuilder: rb,
	}
}

func (b *controllerBuilder) Register(name string, c Controller) {
	if IsDebug {
		logger.Println("Registered controller:", name)
	}

	b.controllers[name] = c
}

func (b *controllerBuilder) Build(app EZApp) error {
	for name, c := range b.controllers {
		if IsDebug {
			logger.Println("Building controller:", name, c)
		}

		var hasAny bool

		// Load optional middleware map
		var m MiddlewareMap
		if cm, ok := c.(ControllerWithMiddleware); ok {
			logger.Println("Controller has middleware:", name)
			m = cm.Middleware(app)
		}

		collect := func(action, method string) []Middleware {
			if m == nil {
				return nil
			}
			out := make([]Middleware, 0, len(m["*"])+len(m[method])+len(m[action]))
			out = append(out, m["*"]...)
			out = append(out, m[method]...)
			out = append(out, m[action]...)
			return out
		}

		if h := c.Index(app); h != nil {
			hasAny = true
			b.routeBuilder.Get("/"+name, Chain(h, collect("index", http.MethodGet)...))
		}
		if h := c.Show(app); h != nil {
			hasAny = true
			b.routeBuilder.Get("/"+name+"/:id", Chain(h, collect("show", http.MethodGet)...))
		}
		if h := c.Edit(app); h != nil {
			hasAny = true
			b.routeBuilder.Get("/"+name+"/:id/edit", Chain(h, collect("edit", http.MethodGet)...))
		}
		if h := c.Post(app); h != nil {
			hasAny = true
			b.routeBuilder.Post("/"+name, Chain(h, collect("post", http.MethodPost)...))
		}
		if h := c.Put(app); h != nil {
			hasAny = true
			b.routeBuilder.Put("/"+name+"/:id", Chain(h, collect("put", http.MethodPut)...))
		}
		if h := c.Delete(app); h != nil {
			hasAny = true
			b.routeBuilder.Delete("/"+name+"/:id", Chain(h, collect("delete", http.MethodDelete)...))
		}
		if h := c.Patch(app); h != nil {
			hasAny = true
			b.routeBuilder.Patch("/"+name+"/:id", Chain(h, collect("patch", http.MethodPatch)...))
		}

		if !hasAny {
			if IsDebug {
				logger.Println("Controller has no methods:", name)
			}
			return fmt.Errorf("controller %q has no methods", name)
		}
	}

	return nil
}
