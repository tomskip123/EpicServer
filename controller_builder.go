package epicserver

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/tomskip123/EpicServer/config"
)

type ControllerBuilder interface {
	Register(name string, c Controller)
	Build(app *EZApp) error
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

func (b *controllerBuilder) Build(app *EZApp) error {
	names := make([]string, 0, len(b.controllers))
	for name := range b.controllers {
		names = append(names, name)
	}
	sort.Strings(names)

	var errs []error

	for _, name := range names {
		c := b.controllers[name]

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

		// Look through extension method defined routes.
		if routes := c.Routes(app); routes != nil {
			// TODO: extract method from map key,
			// register the route with any middleware added via the collect method.
			app.Logger.Info.Println(routes)
			for key, route := range routes {
				routeSplit := strings.Split(key, " ")
				if len(routeSplit) != 2 {
					app.Logger.Error.Printf("route format incorrect for %v", key)
					continue
				}

				method := routeSplit[0]
				path := fmt.Sprintf("/%v%v", name, routeSplit[1])

				if b.isValidMethod(method) {
					switch method {
					case "GET":
						b.routeBuilder.Get(path, Chain(route, collect(key, http.MethodGet)...))
					case "POST":
						b.routeBuilder.Post(path, Chain(route, collect(key, http.MethodPost)...))
					case "PUT":
						b.routeBuilder.Put(path, Chain(route, collect(key, http.MethodPut)...))
					case "PATCH":
						b.routeBuilder.Patch(path, Chain(route, collect(key, http.MethodPatch)...))
					case "DELETE":
						b.routeBuilder.Delete(path, Chain(route, collect(key, http.MethodDelete)...))
					default:
						app.Logger.Error.Printf("method %v is not a valid method", method)
					}
				}
			}
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (b *controllerBuilder) isValidMethod(meth string) bool {
	return meth == "GET" || meth == "POST" || meth == "PATCH" || meth == "PUT" || meth == "DELETE"
}
