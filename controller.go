package epicserver

type ControllerWith[T any] interface {
	Routes(app *EZAppWith[T]) RouteMap
}

type Controller = ControllerWith[struct{}]

// Optional: map-based per-controller middleware.
// Keys: "*", HTTP methods ("GET","POST","PUT","PATCH","DELETE"),
// or action names ("index","show","edit","post","put","delete","patch").
type MiddlewareMap map[string][]Middleware

// ExtensionMap allows controllers to extend uppon base routes.
// the map key should be the path prefixed with the method for example
// GET /route
// POST /route
type RouteMap map[string]Route

type ControllerWithMiddlewareFor[T any] interface {
	ControllerWith[T]
	Middleware(app *EZAppWith[T]) MiddlewareMap
}

type ControllerWithMiddleware = ControllerWithMiddlewareFor[struct{}]
