// Package template provides integration between the EpicServer framework and the
// templ templating library (github.com/a-h/templ). This package makes it easy to
// render templ components in Gin HTTP handlers.
//
// The templ library allows you to write type-safe HTML templates in Go, with
// features like component composition, conditional rendering, and loops.
//
// # Basic Usage Example
//
//	import (
//	    "net/http"
//	    "github.com/gin-gonic/gin"
//	    "github.com/tomskip123/EpicServer/v2/template"
//	    "yourapp/views" // Your templ components
//	)
//
//	func HomeHandler(c *gin.Context) {
//	    // Create a templ component with data
//	    user := User{Name: "John", Email: "john@example.com"}
//	    homeView := views.Home(user)
//
//	    // Render the component with a 200 OK status
//	    if err := template.TemplRender(c, http.StatusOK, homeView); err != nil {
//	        c.String(http.StatusInternalServerError, "Error rendering template")
//	    }
//	}
//
//	// In your router setup:
//	router.GET("/", HomeHandler)
package template

import (
	"github.com/a-h/templ"
	"github.com/gin-gonic/gin"
)

// TemplRender renders a templ component to the HTTP response.
// This function integrates the templ library with Gin's context system,
// making it easy to render templ components in your HTTP handlers.
//
// Parameters:
//   - c: The Gin context for the HTTP request
//   - status: The HTTP status code to set (e.g., http.StatusOK)
//   - template: The templ component to render
//
// Returns:
//   - error: Any error that occurred during rendering
//
// Example:
//
//	func ProfileHandler(c *gin.Context) {
//	    userID := c.Param("id")
//	    user, err := getUserByID(userID)
//	    if err != nil {
//	        c.String(http.StatusNotFound, "User not found")
//	        return
//	    }
//
//	    // Render the profile component
//	    profileView := views.Profile(user)
//	    if err := template.TemplRender(c, http.StatusOK, profileView); err != nil {
//	        c.String(http.StatusInternalServerError, "Error rendering template")
//	    }
//	}
func TemplRender(c *gin.Context, status int, template templ.Component) error {
	c.Status(status)
	return template.Render(c.Request.Context(), c.Writer)
}
