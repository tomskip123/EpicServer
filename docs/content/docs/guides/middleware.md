---
title: "Middleware"
description: "Learn how to use and create middleware in EpicServer."
summary: "A comprehensive guide to using built-in middleware and creating custom middleware in EpicServer."
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 20
toc: true
seo:
  title: "EpicServer Middleware Guide" # custom title (optional)
  description: "Learn how to use built-in middleware and create custom middleware in EpicServer." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Middleware in EpicServer

EpicServer provides several built-in middleware options and supports custom middleware creation.

### Default Middleware

EpicServer includes the following middleware by default:

```go
// These are already applied by default, you don't need to add them manually
defaultLayers := []AppLayer{
    WithLoggerMiddleware(), // Add the logger to the context first
    WithHealthCheck("/health"),
    WithCompression(),      // Compression is already here!
    WithRemoveWWW(),
    WithEnvironment(config.Server.Environment),
}
```

### Compression Middleware

> ⚠️ **Important Note**: Compression middleware is **already included by default** in the server initialization. You do not need to add it manually with `WithCompression()`. Adding it again will result in the middleware being applied twice, which can cause issues.

If you need to customize compression settings, you can replace the default middleware with your own implementation.

```go
func main() {
    // DO NOT add compression middleware like this unless you have a specific reason
    // as it's already included by default:
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // EpicServer.WithCompression(), // This is redundant! Already included by default
        },
    })
}
```

Features:
* Automatic gzip compression
* Smart cache control headers
* Asset-specific caching rules
* Conditional compression based on Accept-Encoding

### CORS Middleware

Configure Cross-Origin Resource Sharing:

```go
func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            EpicServer.WithCors([]string{
                "https://example.com",
                "https://api.example.com",
            }),
        },
    })
}
```

Features:
* Origin validation
* Configurable allowed origins
* Preflight request handling
* Custom headers support
* Credential support

### CSRF Protection

Enable CSRF token validation:

```go
func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            EpicServer.WithCSRFProtection(),
        },
    })
}

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

Features:
* Automatic token generation
* Token validation
* Trusted source bypass
* Custom token storage
* Header/Form support

### WWW Redirect Middleware

Remove 'www' prefix from domains:

```go
func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            EpicServer.WithRemoveWWW(),
        },
    })
}
```

Features:
* Automatic www detection
* Permanent redirects (301)
* HTTPS upgrade support
* Path preservation

### Custom Middleware

Create your own middleware:

> ⚠️ **Important Note**: When adding custom middleware, be aware of the default middleware that's already included (WithLoggerMiddleware, WithHealthCheck, WithCompression, WithRemoveWWW, WithEnvironment). Avoid duplicating functionality that's already provided by default middleware.

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

// Usage
server := EpicServer.NewServer(&EpicServer.NewServerParam{
    AppLayer: []EpicServer.AppLayer{
        MyCustomMiddleware(),
    },
})
```

### Middleware Order

Middleware is executed in the order it's added. Be aware that some middleware is already included by default (as shown in the Compression Middleware section).

```go
// Default middleware is applied first in this order:
// 1. WithLoggerMiddleware()
// 2. WithHealthCheck("/health")
// 3. WithCompression()
// 4. WithRemoveWWW()
// 5. WithEnvironment(config.Server.Environment)

// Then your custom middleware is applied:
server := EpicServer.NewServer(&EpicServer.NewServerParam{
    AppLayer: []EpicServer.AppLayer{
        // DO NOT add middleware that's already included by default
        // EpicServer.WithCompression(),    // WRONG: Already included by default
        
        // DO add custom middleware you need
        EpicServer.WithCors(origins),    // This will be 6th in execution order
        MyCustomMiddleware(),            // This will be 7th in execution order
    },
})
```

When adding your own middleware, remember that it will be executed after the default middleware. If you need to replace or customize default middleware, you should use a different approach (see Custom Configuration section).

### Built-in Security Headers

All responses automatically include security headers:
* X-Content-Type-Options: nosniff
* X-Frame-Options: DENY
* X-XSS-Protection: 1; mode=block
* Strict-Transport-Security: max-age=31536000; includeSubDomains
* Content-Security-Policy: configurable

### Replacing Default Middleware

If you need to replace or customize default middleware (such as compression), you can create a custom server initialization that skips the default middleware:

```go
// Create a server without default middleware
server := &EpicServer.Server{
    Config: EpicServer.defaultConfig(),
    Engine: gin.New(), // Use gin.New() instead of gin.Default() to avoid default middleware
}

// Initialize the logger
server.Logger = EpicServer.defaultLogger(os.Stdout)

// Setup default hooks
server.Hooks = EpicServer.defaultHooks(server)

// Add only the middleware you want
server.Engine.Use(EpicServer.LoggerMiddleware(server.Logger))
server.Engine.Use(EpicServer.RequestTimingMiddleware(server.Logger))
server.Engine.Use(MyCustomCompressMiddleware()) // Your custom compression middleware
server.Engine.Use(EpicServer.RemoveWWWMiddleware())

// Continue with your custom configuration
// ...
```

This approach gives you full control over which middleware is included and in what order. 