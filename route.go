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
	Public  bool // Default false - everything requires auth unless marked public
}

type RouteGroup struct {
	Prefix string
	Routes []Route
	Public bool // Default false - all routes in group require auth unless marked public
}

// Register routes with AppLayer pattern
func WithRoutes(groups ...RouteGroup) AppLayer {
	return func(s *Server) {
		for _, group := range groups {
			ginGroup := s.engine.Group(group.Prefix)
			for _, route := range group.Routes {
				// Route is public if either group or route is marked public
				isPublic := route.Public || group.Public

				var handlers []gin.HandlerFunc
				if isPublic {
					// For public routes, skip the auth middleware
					handlers = []gin.HandlerFunc{s.skipAuth(), gin.HandlerFunc(route.Handler)}
				} else {
					handlers = []gin.HandlerFunc{gin.HandlerFunc(route.Handler)}
				}

				ginGroup.Handle(route.Method, route.Path, handlers...)
			}
		}
	}
}

// Helper middleware to skip auth for public routes
func (s *Server) skipAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("skip_auth", true)
		c.Next()
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

func Public(route Route) Route {
	route.Public = true
	return route
}
