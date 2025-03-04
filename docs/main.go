package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tomskip123/EpicServer/v2"
)

func main() {
	// Define the static directory path - when running from docs directory
	staticDir := "static"

	// Create static directory if it doesn't exist
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		if err := os.MkdirAll(staticDir, 0755); err != nil {
			log.Fatalf("Failed to create static directory: %v", err)
		}
		log.Printf("Created static directory at %s", staticDir)
	}

	// Create a new server with basic configuration
	server := EpicServer.NewServer([]EpicServer.Option{
		EpicServer.SetHost("localhost", 8081),
		EpicServer.SetSecretKey([]byte("your-secret-key")),
		EpicServer.SetEnvironment("development"),
	})

	// Check for initialization errors
	if server.HasErrors() {
		for _, err := range server.GetErrors() {
			log.Fatalf("Server initialization error: %v", err)
		}
	}

	// Get absolute path to static directory
	absStaticPath, err := filepath.Abs(staticDir)
	if err != nil {
		log.Fatalf("Failed to get absolute path: %v", err)
	}

	// Apply application layers for additional functionality
	server.UpdateAppLayer([]EpicServer.AppLayer{
		EpicServer.WithLoggerMiddleware(),
		EpicServer.WithCors([]string{"*"}),
		EpicServer.WithRateLimiter(EpicServer.RateLimiterConfig{
			MaxRequests:   100,
			Interval:      time.Minute,
			BlockDuration: 5 * time.Minute,
			ExcludedPaths: []string{"/health", "/site/*"},
		}),
	})

	// Add routes
	server.UpdateAppLayer([]EpicServer.AppLayer{
		EpicServer.WithRoutes(
			EpicServer.RouteGroup{
				Prefix: "/api",
				Routes: []EpicServer.Route{
					EpicServer.Get("/status", HandleStatus),
					EpicServer.Get("/info", HandleInfo),
				},
			},
		),
	})

	// Serve static files from the static directory
	// Use a specific path prefix instead of root to avoid conflicts
	server.Engine.Static("/site", absStaticPath)

	// Add a redirect from root to the static index.html
	server.Engine.GET("/", func(c *gin.Context) {
		c.Redirect(302, "/site/index.html")
	})

	log.Printf("Starting server on http://localhost:8081")
	log.Printf("Static files are being served from: %s", absStaticPath)
	log.Printf("Access the website at: http://localhost:8081/site/index.html")
	log.Printf("Or simply visit: http://localhost:8081/ for a redirect")

	// Start the server (blocking call)
	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// HandleStatus returns the server status
func HandleStatus(c *gin.Context, s *EpicServer.Server) {
	c.JSON(200, gin.H{
		"status":      "running",
		"server":      "EpicServer",
		"environment": s.Config.Server.Environment,
	})
}

// HandleInfo returns information about the server
func HandleInfo(c *gin.Context, s *EpicServer.Server) {
	c.JSON(200, gin.H{
		"name":        "EpicServer Static Site",
		"version":     "1.0.0",
		"description": "A static website served by EpicServer",
		"staticPath":  "static",
		"endpoints": []string{
			"/health",
			"/api/status",
			"/api/info",
			"/site/",
		},
	})
}
