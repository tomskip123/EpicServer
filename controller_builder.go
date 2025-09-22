package epicserver

import (
	"fmt"
)

type ControllerBuilder interface {
	Register(name string, c Controller)
	Build() error
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

func (b *controllerBuilder) Build() error {
	for name, c := range b.controllers {
		if IsDebug {
			logger.Println("Building controller:", name, c)
		}

		// bind controller methods to routes
		// e.g. GET /resource -> c.Index()
		if c.Index() != nil {
			route := "/" + name
			b.routeBuilder.Get(route, c.Index())

		} else if c.Show() != nil {
			route := "/" + name + "/:id"
			b.routeBuilder.Get(route, c.Show())
		} else if c.Edit() != nil {
			route := "/" + name + "/:id/edit"
			b.routeBuilder.Get(route, c.Edit())
		} else if c.Post() != nil {
			route := "/" + name
			b.routeBuilder.Post(route, c.Post())
		} else if c.Put() != nil {
			route := "/" + name + "/:id"
			b.routeBuilder.Put(route, c.Put())
		} else if c.Delete() != nil {
			route := "/" + name + "/:id"
			b.routeBuilder.Delete(route, c.Delete())
		} else if c.Patch() != nil {
			route := "/" + name + "/:id"
			b.routeBuilder.Patch(route, c.Patch())
		} else {
			if IsDebug {
				logger.Println("Controller has no methods:", name)
			}

			return fmt.Errorf("controller %q has no methods", name)
		}
	}

	return nil
}
