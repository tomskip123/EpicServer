package epicserver

type Controller interface {
	Index(app EZApp) Route // GET /resource
	Show(app EZApp) Route  // GET /resource/:id
	Edit(app EZApp) Route  // GET /resource/:id/edit

	Post(app EZApp) Route   // POST /resource
	Put(app EZApp) Route    // PUT /resource/:id
	Delete(app EZApp) Route // DELETE /resource/:id
	Patch(app EZApp) Route  // PATCH /resource/:id
}

// Optional: map-based per-controller middleware.
// Keys: "*", HTTP methods ("GET","POST","PUT","PATCH","DELETE"),
// or action names ("index","show","edit","post","put","delete","patch").
type MiddlewareMap map[string][]Middleware

type ControllerWithMiddleware interface {
	Controller
	Middleware(app EZApp) MiddlewareMap
}
