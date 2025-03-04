---
title: "Logging"
description: "Learn how to use the logging system in EpicServer."
summary: "A comprehensive guide to configuring and using the structured logging system in EpicServer."
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 60
toc: true
seo:
  title: "EpicServer Logging Guide" # custom title (optional)
  description: "Learn how to configure and use structured logging in EpicServer." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Logging in EpicServer

EpicServer provides a powerful structured logging system that helps you track application events, errors, and performance metrics. This guide will show you how to configure and use the logging system effectively.

### Basic Logging

The logging system is automatically initialized when you create a new server instance. You can access the logger through the server object:

```go
package main

import (
    "github.com/tomskip123/EpicServer/v2"
)

func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{})
    
    // Access the logger
    logger := server.Logger
    
    // Log messages at different levels
    logger.Debug("Debug message")
    logger.Info("Info message")
    logger.Warn("Warning message")
    logger.Error("Error message")
    
    server.Start()
}
```

### Structured Logging

EpicServer v2.0.0+ supports structured logging, which allows you to include additional context with your log messages:

```go
// Log with structured fields
logger.Info("User logged in", map[string]interface{}{
    "user_id": "123",
    "email":   "user@example.com",
    "ip":      "192.168.1.1",
})

// Log errors with context
err := someFunction()
if err != nil {
    logger.Error("Operation failed", map[string]interface{}{
        "operation": "user_update",
        "error":     err.Error(),
    })
}
```

### Configuring Log Levels

You can configure the log level when creating the server:

```go
server := EpicServer.NewServer(&EpicServer.NewServerParam{
    AppLayer: []EpicServer.AppLayer{
        EpicServer.WithLogConfig(EpicServer.LogConfig{
            Level: "debug", // Options: debug, info, warn, error
        }),
    },
})
```

### Configuring Log Format

EpicServer supports multiple log formats:

```go
server := EpicServer.NewServer(&EpicServer.NewServerParam{
    AppLayer: []EpicServer.AppLayer{
        EpicServer.WithLogConfig(EpicServer.LogConfig{
            Format: "json", // Options: text, json
        }),
    },
})
```

### Environment Variables for Logging

You can also configure logging using environment variables:

```env
LOG_LEVEL=debug
LOG_FORMAT=json
```

### Module-Based Logging (v2.0.2+)

EpicServer v2.0.2 introduced module-based logging, which allows you to organize logs by module and set different log levels for different parts of your application:

```go
package main

import (
    "github.com/tomskip123/EpicServer/v2"
)

func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            EpicServer.WithLogConfig(EpicServer.LogConfig{
                Level:  "info",
                Format: "json",
            }),
        },
    })
    
    // Create module loggers
    authLogger := server.Logger.Module("auth")
    dbLogger := server.Logger.Module("db")
    apiLogger := server.Logger.Module("api")
    
    // Use module loggers
    authLogger.Info("Auth system initialized")
    dbLogger.Debug("Database connection established")
    apiLogger.Warn("API rate limit reached", map[string]interface{}{
        "endpoint": "/users",
        "ip":       "192.168.1.1",
    })
    
    server.Start()
}
```

### Hierarchical Module Logging

Module loggers can be organized hierarchically:

```go
// Create parent module
apiLogger := server.Logger.Module("api")

// Create child modules
usersLogger := apiLogger.Module("users")
productsLogger := apiLogger.Module("products")

// Log with child modules
usersLogger.Info("User created", map[string]interface{}{"user_id": "123"})
productsLogger.Debug("Product fetched", map[string]interface{}{"product_id": "456"})
```

### Setting Log Levels for Modules

You can set different log levels for different modules:

```go
// Set global log level
server.Logger.SetLevel("info")

// Set module-specific log levels
authLogger := server.Logger.Module("auth")
authLogger.SetLevel("debug")

dbLogger := server.Logger.Module("db")
dbLogger.SetLevel("warn")
```

### Log Level Inheritance

Child modules inherit log levels from their parents unless explicitly overridden:

```go
// Set parent module level
apiLogger := server.Logger.Module("api")
apiLogger.SetLevel("info")

// Child modules inherit parent level
usersLogger := apiLogger.Module("users")
productsLogger := apiLogger.Module("products")

// Override level for specific child
productsLogger.SetLevel("debug")
```

### Custom Log Registry

For advanced use cases, you can create a custom log registry:

```go
// Create custom registry
registry := EpicServer.NewLogRegistry()

// Create root logger
logger := registry.GetLogger()
logger.SetLevel("info")

// Create module loggers
authLogger := registry.GetLogger("auth")
dbLogger := registry.GetLogger("db")

// Set module levels
authLogger.SetLevel("debug")
dbLogger.SetLevel("warn")
```

## Logging in Route Handlers

You can access the logger in your route handlers:

```go
func UserHandler(c *gin.Context, s *EpicServer.Server) {
    // Get logger
    logger := s.Logger
    
    // Create module logger for this handler
    userLogger := logger.Module("handlers.user")
    
    userID := c.Param("id")
    userLogger.Info("Fetching user", map[string]interface{}{
        "user_id": userID,
        "method":  c.Request.Method,
        "path":    c.Request.URL.Path,
    })
    
    // Process request...
    
    userLogger.Debug("User request completed", map[string]interface{}{
        "user_id":     userID,
        "status_code": 200,
        "duration_ms": 42,
    })
}
```

## Logging Middleware

EpicServer automatically logs HTTP requests using middleware. You can customize this behavior:

```go
server := EpicServer.NewServer(&EpicServer.NewServerParam{
    AppLayer: []EpicServer.AppLayer{
        EpicServer.WithLogConfig(EpicServer.LogConfig{
            Level:            "info",
            Format:           "json",
            LogRequests:      true,
            LogRequestBody:   false,
            LogResponseBody:  false,
            LogRequestHeader: false,
        }),
    },
})
```

## Complete Logging Example

Here's a complete example demonstrating various logging features:

```go
package main

import (
    "time"
    
    "github.com/gin-gonic/gin"
    "github.com/tomskip123/EpicServer/v2"
)

// UserService handles user-related operations
type UserService struct {
    logger EpicServer.Logger
}

// NewUserService creates a new user service
func NewUserService(logger EpicServer.Logger) *UserService {
    return &UserService{
        logger: logger.Module("services.user"),
    }
}

// GetUser retrieves a user by ID
func (s *UserService) GetUser(id string) (map[string]interface{}, error) {
    s.logger.Debug("Getting user", map[string]interface{}{
        "user_id": id,
    })
    
    // Simulate database operation
    time.Sleep(100 * time.Millisecond)
    
    // Return mock user
    user := map[string]interface{}{
        "id":    id,
        "name":  "John Doe",
        "email": "john@example.com",
    }
    
    s.logger.Info("User retrieved", map[string]interface{}{
        "user_id": id,
    })
    
    return user, nil
}

// GetUserHandler handles user GET requests
func GetUserHandler(c *gin.Context, s *EpicServer.Server) {
    // Create handler logger
    logger := s.Logger.Module("handlers.user")
    
    // Create user service
    userService := NewUserService(s.Logger)
    
    // Get user ID from path
    userID := c.Param("id")
    
    // Log request
    logger.Info("User request received", map[string]interface{}{
        "user_id":  userID,
        "method":   c.Request.Method,
        "path":     c.Request.URL.Path,
        "client_ip": c.ClientIP(),
    })
    
    // Get user
    start := time.Now()
    user, err := userService.GetUser(userID)
    duration := time.Since(start)
    
    // Handle error
    if err != nil {
        logger.Error("Failed to get user", map[string]interface{}{
            "user_id": userID,
            "error":   err.Error(),
            "duration_ms": duration.Milliseconds(),
        })
        
        c.JSON(500, gin.H{"error": "Failed to get user"})
        return
    }
    
    // Log success
    logger.Debug("User request completed", map[string]interface{}{
        "user_id":     userID,
        "status_code": 200,
        "duration_ms": duration.Milliseconds(),
    })
    
    // Return user
    c.JSON(200, user)
}

func main() {
    // Initialize server
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // Configure logging
            EpicServer.WithLogConfig(EpicServer.LogConfig{
                Level:  "debug",
                Format: "json",
            }),
            
            // Add routes
            EpicServer.WithRoutes(
                EpicServer.RouteGroup{
                    Prefix: "/api/v1",
                    Routes: []EpicServer.Route{
                        EpicServer.Get("/users/:id", GetUserHandler),
                    },
                },
            ),
        },
    })
    
    // Configure module loggers
    apiLogger := server.Logger.Module("api")
    apiLogger.SetLevel("debug")
    
    dbLogger := server.Logger.Module("db")
    dbLogger.SetLevel("info")
    
    authLogger := server.Logger.Module("auth")
    authLogger.SetLevel("warn")
    
    // Log server startup
    server.Logger.Info("Server starting", map[string]interface{}{
        "host": "localhost",
        "port": 8080,
        "env":  "development",
    })
    
    // Start the server
    server.Start()
}
```

## Best Practices for Logging

### 1. Use Appropriate Log Levels

* **Debug**: Detailed information useful for debugging
* **Info**: General information about application operation
* **Warn**: Potential issues that don't prevent operation
* **Error**: Errors that prevent normal operation

### 2. Include Contextual Information

Always include relevant context with your log messages:

```go
logger.Info("User authentication", map[string]interface{}{
    "user_id":   userID,
    "ip":        clientIP,
    "success":   true,
    "auth_type": "oauth",
})
```

### 3. Use Module-Based Logging

Organize your logs by module to make them easier to filter and analyze:

```go
authLogger := server.Logger.Module("auth")
dbLogger := server.Logger.Module("db")
apiLogger := server.Logger.Module("api")
```

### 4. Log Request/Response Information

Log important information about HTTP requests and responses:

```go
logger.Info("API request", map[string]interface{}{
    "method":      c.Request.Method,
    "path":        c.Request.URL.Path,
    "client_ip":   c.ClientIP(),
    "status_code": statusCode,
    "duration_ms": duration.Milliseconds(),
})
```

### 5. Log Performance Metrics

Include timing information for important operations:

```go
start := time.Now()
result, err := performOperation()
duration := time.Since(start)

logger.Info("Operation completed", map[string]interface{}{
    "operation":   "data_processing",
    "duration_ms": duration.Milliseconds(),
    "records":     len(result),
})
```

### 6. Configure Production Logging

In production, consider these settings:

```go
server := EpicServer.NewServer(&EpicServer.NewServerParam{
    AppLayer: []EpicServer.AppLayer{
        EpicServer.WithLogConfig(EpicServer.LogConfig{
            Level:            "info",  // Avoid debug in production
            Format:           "json",  // JSON for log aggregation
            LogRequests:      true,
            LogRequestBody:   false,   // Avoid logging sensitive data
            LogResponseBody:  false,   // Avoid excessive logging
        }),
    },
})
``` 