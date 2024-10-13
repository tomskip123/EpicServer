package middleware

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
)

func AnalyticsMiddleware() gin.HandlerFunc {
	// analyticsDb := app.Database.

	return func(c *gin.Context) {
		go func() {
			// Log the event before request
			event := map[string]interface{}{
				"event":     c.Request.URL.Path,
				"user_id":   c.GetString("auth_user"), // Assuming user_id is in context
				"timestamp": time.Now(),
				"metadata": map[string]interface{}{
					"method": c.Request.Method,
					"ip":     c.ClientIP(),
				},
			}

			fmt.Println(event)
		}()

		// Insert into MongoDB (assuming a MongoDB client is initialized)
		// analyticsCollection.InsertOne(context.TODO(), event)

		// Continue with request
		c.Next()
	}
}
