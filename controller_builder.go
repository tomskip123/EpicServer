package epicserver

import (
	"fmt"
	"net/http"

	"github.com/tomskip123/EpicServer/config"
)

type ControllerBuilder interface {
	Register(name string, c Controller)
	Build(app EZApp) error
}

type controllerBuilder struct {
	controllers  map[string]Controller
	routeBuilder *RouteBuilder
	logger       *Logger
	Config       *config.Config
}

func newControllerBuilder(rb *RouteBuilder) ControllerBuilder {
	return &controllerBuilder{
		controllers:  make(map[string]Controller),
		routeBuilder: rb,
		logger:       rb.Logger, // controller relies on route builder so we can rely on routebuilder logger
		Config:       rb.Config, // controller relies on route builder so we can rely on routebuilder config
	}
}

func (b *controllerBuilder) Register(name string, c Controller) {
	logName := fmt.Sprintf("%T", c)
	b.logger.Info.Printf("Registered controller: %v", logName)

	b.controllers[name] = c
}

func (b *controllerBuilder) Build(app EZApp) error {
	for name, c := range b.controllers {
		var hasAny bool

		// Load optional middleware map
		var m MiddlewareMap
		if cm, ok := c.(ControllerWithMiddleware); ok {
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
			b.logger.Info.Println("Controller has no methods:", name)
			return fmt.Errorf("controller %q has no methods", name)
		}
	}

	return nil
}
