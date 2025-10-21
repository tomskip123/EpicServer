package epicserver

type Controller interface {
	Routes(app *EZApp) RouteMap
}

// Optional: map-based per-controller middleware.
// Keys: "*", HTTP methods ("GET","POST","PUT","PATCH","DELETE"),
// or action names ("index","show","edit","post","put","delete","patch").
type MiddlewareMap map[string][]Middleware

// ExtensionMap allows controllers to extend uppon base routes.
// the map key should be the path prefixed with the method for example
// GET /route
// POST /route
type RouteMap map[string]Route

type ControllerWithMiddleware interface {
	Controller
	Middleware(app *EZApp) MiddlewareMap
}
