package EpicServer

import (
	"github.com/gin-gonic/gin"
)

// HandlerFunc defines a function that handles HTTP requests with access to both
// the Gin context and the server instance.
type HandlerFunc func(*gin.Context, *Server)

// Route defines an HTTP route with its method, path and handler.
type Route struct {
	// Method is the HTTP method (GET, POST, etc.)
	Method string
	// Path is the URL path for the route
	Path string
	// Handler is the function that processes the request
	Handler HandlerFunc
}

// RouteGroup represents a group of routes with a common prefix.
type RouteGroup struct {
	// Prefix is prepended to all routes in the group
	Prefix string
	// Routes contains the individual route definitions
	Routes []Route
}

// WithRoutes registers route groups with the server.
// Example usage:
//
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServer.WithRoutes(
//	        EpicServer.RouteGroup{
//	            Prefix: "/api/v1",
//	            Routes: []EpicServer.Route{
//	                EpicServer.Get("/users", HandleUsers),
//	            },
//	        },
//	    ),
//	})
func WithRoutes(groups ...RouteGroup) AppLayer {
	return func(s *Server) {
		for _, group := range groups {
			ginGroup := s.Engine.Group(group.Prefix)
			for _, route := range group.Routes {
				handler := func(c *gin.Context) {
					route.Handler(c, s)
				}
				handlers := []gin.HandlerFunc{handler}

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
