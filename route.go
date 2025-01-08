package EpicServer

import (
	"github.com/gin-gonic/gin"
)

// Route handler type matching gin.HandlerFunc
type HandlerFunc func(*gin.Context)

// Route definition structure
type Route struct {
	Method  string
	Path    string
	Handler HandlerFunc
}

type RouteGroup struct {
	Prefix string
	Routes []Route
}

// Register routes with AppLayer pattern
func WithRoutes(groups ...RouteGroup) AppLayer {
	return func(s *Server) {
		for _, group := range groups {
			ginGroup := s.engine.Group(group.Prefix)
			for _, route := range group.Routes {
				handlers := []gin.HandlerFunc{gin.HandlerFunc(route.Handler)}

				ginGroup.Handle(route.Method, route.Path, handlers...)
			}
		}
	}
}

// Helper functions
func Post(path string, handler HandlerFunc) Route {
	return Route{
		Method:  "POST",
		Path:    path,
		Handler: handler,
	}
}

func Get(path string, handler HandlerFunc) Route {
	return Route{
		Method:  "GET",
		Path:    path,
		Handler: handler,
	}
}

func Put(path string, handler HandlerFunc) Route {
	return Route{
		Method:  "PUT",
		Path:    path,
		Handler: handler,
	}
}

func Patch(path string, handler HandlerFunc) Route {
	return Route{
		Method:  "PATCH",
		Path:    path,
		Handler: handler,
	}
}

func Delete(path string, handler HandlerFunc) Route {
	return Route{
		Method:  "DELETE",
		Path:    path,
		Handler: handler,
	}
}
