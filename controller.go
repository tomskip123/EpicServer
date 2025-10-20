package epicserver

type Controller interface {
	Index(app *EZApp) Route // GET /resource
	Show(app *EZApp) Route  // GET /resource/:id
	Edit(app *EZApp) Route  // GET /resource/:id/edit

	Post(app *EZApp) Route          // POST /resource
	Put(app *EZApp) Route           // PUT /resource/:id
	Delete(app *EZApp) Route        // DELETE /resource/:id
	Patch(app *EZApp) Route         // PATCH /resource/:id
	Extend(app *EZApp) ExtensionMap // method that allows you to register custom routes within the same controller.
}

// Optional: map-based per-controller middleware.
// Keys: "*", HTTP methods ("GET","POST","PUT","PATCH","DELETE"),
// or action names ("index","show","edit","post","put","delete","patch").
type MiddlewareMap map[string][]Middleware

// ExtensionMap allows controllers to extend uppon base routes.
// the map key should be the path prefixed with the method for example
// GET /route
// POST /route
type ExtensionMap map[string]Route

type ControllerWithMiddleware interface {
	Controller
	Middleware(app *EZApp) MiddlewareMap
}
