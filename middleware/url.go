package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func RemoveWWW() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.Host, "www.") {
			newHost := strings.TrimPrefix(c.Request.Host, "www.")
			newURL := c.Request.URL
			newURL.Host = newHost
			newURL.Scheme = "https"
			c.Redirect(http.StatusMovedPermanently, newURL.String())
			c.Abort()
			return
		}
		c.Next()
	}
}
