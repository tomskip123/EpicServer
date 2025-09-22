package epicserver

type Controller interface {
	Index() Route // GET /resource
	Show() Route  // GET /resource/:id
	Edit() Route  // GET /resource/:id/edit

	Post() Route   // POST /resource
	Put() Route    // PUT /resource/:id
	Delete() Route // DELETE /resource/:id
	Patch() Route  // PATCH /resource/:id
}
