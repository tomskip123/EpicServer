---
title: "Architecture"
description: "Overview of EpicServer's architecture and design principles."
summary: "Learn about the core architecture and design principles behind EpicServer."
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 10
toc: true
seo:
  title: "EpicServer Architecture" # custom title (optional)
  description: "Detailed overview of EpicServer's architecture, components, and design principles." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Core Architecture

EpicServer is built on top of the Gin framework, providing a powerful and flexible foundation for building web applications in Go. The architecture is designed to be modular, extensible, and production-ready.

### Key Components

1. **Server**: The central component that manages the HTTP server lifecycle and coordinates all other components.
2. **Router**: Handles HTTP request routing and middleware management.
3. **Logger**: Provides structured logging capabilities.
4. **Database Adapters**: Connects to various database systems.
5. **Cache System**: Provides in-memory caching capabilities.
6. **Authentication**: Manages user authentication and session handling.
7. **Middleware**: Processes requests before they reach route handlers.

### Server Lifecycle

The server lifecycle consists of the following stages:

1. **Initialization**: Create a new server instance with configuration options.
2. **Configuration**: Apply additional configuration through app layers.
3. **Starting**: Start the HTTP server and begin accepting connections.
4. **Running**: Process incoming HTTP requests.
5. **Stopping**: Gracefully shut down the server.

```go
// Initialization
server := EpicServer.NewServer([]EpicServer.Option{
    EpicServer.SetHost("localhost", 8080),
    EpicServer.SetSecretKey([]byte("your-secret-key")),
})

// Configuration
server.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithHealthCheck("/health"),
    EpicServer.WithEnvironment("development"),
})

// Starting
server.Start()

// Stopping (typically in a signal handler)
server.Stop()
```

## Configuration System

EpicServer uses an options pattern for configuration, allowing for flexible and extensible configuration.

### Options Pattern

The options pattern allows for a clean and flexible way to configure the server:

```go
server := EpicServer.NewServer([]EpicServer.Option{
    EpicServer.SetHost("localhost", 8080),
    EpicServer.SetSecretKey([]byte("your-secret-key")),
})
```

### App Layers

App layers are used to add functionality to the server after initialization:

```go
server.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithHealthCheck("/health"),
    EpicServer.WithEnvironment("development"),
    EpicServer.WithCors([]string{"https://example.com"}),
})
```

## Middleware Architecture

Middleware in EpicServer follows a pipeline pattern, where each middleware can process the request before and after the next middleware or route handler.

### Default Middleware

EpicServer includes several default middleware components:

```go
// These are already applied by default
defaultLayers := []AppLayer{
    WithLoggerMiddleware(), // Add the logger to the context first
    WithHealthCheck("/health"),
    WithCompression(),
    WithRemoveWWW(),
    WithEnvironment(config.Server.Environment),
}
```

### Custom Middleware

You can create custom middleware to add your own functionality:

```go
func MyCustomMiddleware() EpicServer.AppLayer {
    return func(s *EpicServer.Server) {
        s.Engine.Use(func(c *gin.Context) {
            // Pre-processing
            c.Set("custom_key", "custom_value")
            
            c.Next()
            
            // Post-processing
            status := c.Writer.Status()
            if status >= 500 {
                s.Logger.Error("Server error occurred")
            }
        })
    }
}
```

## Routing System

EpicServer's routing system is built on top of Gin's router, providing a flexible and powerful way to define routes.

### Route Groups

Routes can be organized into groups with common prefixes:

```go
EpicServer.WithRoutes(
    EpicServer.RouteGroup{
        Prefix: "/api/v1",
        Routes: []EpicServer.Route{
            EpicServer.Get("/users", HandleGetUsers),
            EpicServer.Post("/users", HandleCreateUser),
        },
    },
    EpicServer.RouteGroup{
        Prefix: "/admin",
        Routes: []EpicServer.Route{
            EpicServer.Get("/stats", HandleAdminStats),
        },
    },
)
```

### Route Handlers

Route handlers have access to both the Gin context and the server instance:

```go
func HandleGetUsers(c *gin.Context, s *EpicServer.Server) {
    // Access server components
    db := EpicServerDb.GetMongoClient(s, "default")
    
    // Use gin context
    userId := c.Param("id")
    
    // Send response
    c.JSON(200, gin.H{"message": "success"})
}
```

## Database Architecture

EpicServer supports multiple database adapters, allowing you to use different database systems in your application.

### Database Adapters

- **MongoDB**: Connect to MongoDB databases.
- **PostgreSQL**: Connect to PostgreSQL databases.
- **MySQL**: Connect to MySQL databases.
- **GORM**: Use GORM ORM with various database backends.

### Multiple Database Connections

You can configure multiple database connections with different connection names:

```go
server.UpdateAppLayer([]EpicServer.AppLayer{
    // Configure multiple databases
    EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
        ConnectionName: "users",
        URI:           "mongodb://localhost:27017",
        DatabaseName:  "users",
    }),
    EpicServerDb.WithPostgres(EpicServerDb.PostgresConfig{
        ConnectionName: "products",
        Host:          "localhost",
        Database:      "products",
    }),
})
```

## Authentication System

EpicServer provides a flexible authentication system supporting multiple providers and custom authentication hooks.

### Authentication Providers

- **Google**: OAuth authentication with Google.
- **Basic Auth**: Username/password authentication.
- **Custom Providers**: Implement your own authentication providers.

### Authentication Hooks

You can implement custom authentication hooks to integrate with your user management system:

```go
type MyAuthHooks struct {
    db *Database
}

func (h *MyAuthHooks) OnUserCreate(user EpicServer.Claims) (string, error) {
    // Create user in database
    return userID, nil
}

func (h *MyAuthHooks) GetUserOrCreate(user EpicServer.Claims) (*EpicServer.CookieContents, error) {
    // Get or create user and return session data
    return &EpicServer.CookieContents{
        UserId:     user.UserID,
        Email:      user.Email,
        SessionId:  generateSessionID(),
        IsLoggedIn: true,
        ExpiresOn:  time.Now().Add(time.Hour * 24),
    }, nil
}
```

## Logging System

EpicServer includes a structured logging system that provides rich logging capabilities.

### Structured Logging

Structured logging allows for more detailed and machine-readable logs:

```go
s.Logger.Info("User authenticated", 
    EpicServer.F("user_id", userID), 
    EpicServer.F("ip", ip),
    EpicServer.F("duration_ms", authDuration.Milliseconds()))
```

### Module-Based Logging

Module-based logging allows you to control log levels for specific components:

```go
// Set log level for specific modules
s.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithLogLevel(EpicServer.LogLevelInfo),
    EpicServer.WithModuleLogLevel("auth", EpicServer.LogLevelDebug),
    EpicServer.WithModuleLogLevel("db", EpicServer.LogLevelError),
})

// Create module-specific loggers
authLogger := s.Logger.WithModule("auth")
dbLogger := s.Logger.WithModule("db")
```

## Security Architecture

EpicServer includes several security features to help you build secure applications.

### Security Headers

All responses automatically include security headers:
* X-Content-Type-Options: nosniff
* X-Frame-Options: DENY
* X-XSS-Protection: 1; mode=block
* Strict-Transport-Security: max-age=31536000; includeSubDomains
* Content-Security-Policy: configurable

### CSRF Protection

EpicServer includes CSRF protection to prevent cross-site request forgery attacks:

```go
// Enable CSRF protection
server.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithCSRFProtection(),
})

// In your handlers
func MyHandler(c *gin.Context) {
    // Generate CSRF token
    token, _ := EpicServer.GenerateCSRFToken()
    
    // Validate token in POST/PUT/DELETE requests
    if !EpicServer.IsTrustedSource(c.Request) {
        // Handle CSRF validation
    }
}
```

### Rate Limiting

EpicServer includes rate limiting to prevent abuse:

```go
// Add rate limiting
server.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithRateLimiter(EpicServer.RateLimiterConfig{
        MaxRequests: 100,
        Interval: time.Minute,
        BlockDuration: 5 * time.Minute,
        ExcludedPaths: []string{"/health", "/static/*"},
    }),
})
``` 