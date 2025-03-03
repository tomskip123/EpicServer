---
title: "Middleware"
description: "Learn how to use and create middleware in EpicServer."
summary: "Complete guide to using and implementing middleware in EpicServer."
date: 2023-09-07T16:06:50+02:00
lastmod: 2023-09-07T16:06:50+02:00
draft: false
weight: 20
toc: true
seo:
  title: "EpicServer Middleware Guide" # custom title (optional)
  description: "Learn how to use built-in middleware and create custom middleware in EpicServer." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Introduction to Middleware

Middleware are functions that process HTTP requests before they reach your route handlers or after the response is generated. They are a powerful way to add common functionality to your web application, such as authentication, logging, CORS support, and more.

## Using Built-in Middleware

EpicServer comes with several built-in middleware functions that you can use in your application:

### Logger Middleware

The logger middleware logs information about incoming HTTP requests:

```go
server := epicserver.NewServer(&epicserver.Config{})
server.Use(epicserver.Logger())
```

### Recovery Middleware

The recovery middleware recovers from panics and returns a 500 response:

```go
server.Use(epicserver.Recovery())
```

### CORS Middleware

The CORS middleware adds Cross-Origin Resource Sharing headers to responses:

```go
corsConfig := epicserver.CORSConfig{
    AllowOrigins:     []string{"https://example.com"},
    AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
    AllowHeaders:     []string{"Origin", "Content-Type"},
    ExposeHeaders:    []string{"Content-Length"},
    AllowCredentials: true,
    MaxAge:           12 * time.Hour,
}

server.Use(epicserver.CORSWithConfig(corsConfig))
```

### Compression Middleware

The compression middleware compresses response data:

```go
server.Use(epicserver.Compression())
```

## Creating Custom Middleware

You can create your own middleware functions to add custom functionality:

```go
func AuthMiddleware() epicserver.HandlerFunc {
    return func(ctx *epicserver.Context) {
        // Get token from request
        token := ctx.GetHeader("Authorization")
        
        // Validate token
        if !validateToken(token) {
            ctx.AbortWithStatusJSON(http.StatusUnauthorized, epicserver.H{
                "error": "Unauthorized",
            })
            return
        }
        
        // Set user info in context
        userID := getUserIDFromToken(token)
        ctx.Set("userID", userID)
        
        // Continue to the next middleware or handler
        ctx.Next()
    }
}
```

Then use your custom middleware:

```go
// Apply to all routes
server.Use(AuthMiddleware())

// Or apply to specific route groups
api := server.Group("/api")
api.Use(AuthMiddleware())
```

## Middleware Order

The order of middleware is important. Middleware are executed in the order they are added:

```go
server.Use(epicserver.Logger())   // Executed first
server.Use(epicserver.Recovery()) // Executed second
server.Use(AuthMiddleware())      // Executed third
```

## Aborting Middleware Chain

Middleware can abort the request handling pipeline using `Abort` or `AbortWithStatus`:

```go
func RateLimiter() epicserver.HandlerFunc {
    return func(ctx *epicserver.Context) {
        if isRateLimited(ctx.ClientIP()) {
            ctx.AbortWithStatus(http.StatusTooManyRequests)
            return
        }
        ctx.Next()
    }
}
```

## Best Practices

1. **Keep Middleware Focused**: Each middleware should have a single responsibility.
2. **Consider Performance**: Be aware of the performance impact of your middleware, especially for high-traffic applications.
3. **Order Matters**: Place critical middleware like recovery and security early in the chain.
4. **Use Middleware for Cross-Cutting Concerns**: Authentication, logging, error handling, etc., are perfect use cases for middleware.
5. **Test Middleware Independently**: Write unit tests for your middleware functions. 