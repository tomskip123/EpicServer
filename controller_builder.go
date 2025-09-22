package epicserver

import (
	"fmt"
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

		// bind controller methods to routes
		// e.g. GET /resource -> c.Index()
		if result := c.Index(app); result != nil {
			route := "/" + name
			b.routeBuilder.Get(route, result)
		} else if result := c.Show(app); result != nil {
			route := "/" + name + "/:id"
			b.routeBuilder.Get(route, result)
		} else if result := c.Edit(app); result != nil {
			route := "/" + name + "/:id/edit"
			b.routeBuilder.Get(route, result)
		} else if result := c.Post(app); result != nil {
			route := "/" + name
			b.routeBuilder.Post(route, result)
		} else if result := c.Put(app); result != nil {
			route := "/" + name + "/:id"
			b.routeBuilder.Put(route, result)
		} else if result := c.Delete(app); result != nil {
			route := "/" + name + "/:id"
			b.routeBuilder.Delete(route, result)
		} else if result := c.Patch(app); result != nil {
			route := "/" + name + "/:id"
			b.routeBuilder.Patch(route, result)
		} else {
			if IsDebug {
				logger.Println("Controller has no methods:", name)
			}

			return fmt.Errorf("controller %q has no methods", name)
		}
	}

	return nil
}
