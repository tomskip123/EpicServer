package template

import (
	"github.com/a-h/templ"
	"github.com/gin-gonic/gin"
)

func TemplRender(c *gin.Context, status int, template templ.Component) error {
	c.Status(status)
	return template.Render(c.Request.Context(), c.Writer)
}
