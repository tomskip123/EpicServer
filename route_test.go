package EpicServer

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// Test for WithRoutes function
func TestWithRoutes(t *testing.T) {
	// Set up a new Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	s := &Server{Engine: router}

	// Define a test route group
	group := RouteGroup{
		Prefix: "/api",
		Routes: []Route{
			{Method: "GET", Path: "/test", Handler: func(c *gin.Context, s *Server) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			}},
		},
	}

	// Register the routes
	WithRoutes(group)(s)

	// Create a test request
	req, _ := http.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Check the response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", w.Code)
	}
	if w.Body.String() != "{\"message\":\"success\"}" {
		t.Errorf("Expected response body to be '{\"message\":\"success\"}', got '%s'", w.Body.String())
	}
}

func TestPost(t *testing.T) {
	route := Post("/test", func(c *gin.Context, s *Server) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	if route.Method != "POST" || route.Path != "/test" {
		t.Errorf("Expected method POST and path /test, got %s and %s", route.Method, route.Path)
	}
}

func TestGet(t *testing.T) {
	route := Get("/test", func(c *gin.Context, s *Server) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	if route.Method != "GET" || route.Path != "/test" {
		t.Errorf("Expected method GET and path /test, got %s and %s", route.Method, route.Path)
	}
}

func TestPut(t *testing.T) {
	route := Put("/test", func(c *gin.Context, s *Server) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	if route.Method != "PUT" || route.Path != "/test" {
		t.Errorf("Expected method PUT and path /test, got %s and %s", route.Method, route.Path)
	}
}

func TestPatch(t *testing.T) {
	route := Patch("/test", func(c *gin.Context, s *Server) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	if route.Method != "PATCH" || route.Path != "/test" {
		t.Errorf("Expected method PATCH and path /test, got %s and %s", route.Method, route.Path)
	}
}

func TestDelete(t *testing.T) {
	route := Delete("/test", func(c *gin.Context, s *Server) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	if route.Method != "DELETE" || route.Path != "/test" {
		t.Errorf("Expected method DELETE and path /test, got %s and %s", route.Method, route.Path)
	}
}

func TestWithRoutes2(t *testing.T) {
	router := gin.Default()
	server := &Server{Engine: router}
	group := RouteGroup{
		Prefix: "/api",
		Routes: []Route{
			Post("/test", func(c *gin.Context, s *Server) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			}),
		},
	}
	WithRoutes(group)(server)

	// Test the registered route
	req, _ := http.NewRequest("POST", "/api/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %d", w.Code)
	}
}
