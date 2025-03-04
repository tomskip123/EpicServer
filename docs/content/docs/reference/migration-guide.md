---
title: "Migration Guide"
description: "Guide for migrating from EpicServer v1.x to v2.x."
summary: "Learn how to upgrade your application from EpicServer v1.x to v2.x."
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 20
toc: true
seo:
  title: "EpicServer Migration Guide" # custom title (optional)
  description: "Comprehensive guide for migrating from EpicServer v1.x to v2.x with code examples." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Important Note on Versions

> **Version 2.x is now the only supported version of EpicServer.** Version 1.x is deprecated and will not receive updates or security patches. All users are strongly encouraged to migrate to v2.x as soon as possible.

To install the latest v2 version:

```bash
go get github.com/tomskip123/EpicServer/v2
```

## Upgrading to v2.0.0

Version 2.0.0 introduces several breaking changes to improve error handling, security, and maintainability. Follow this guide to update your application.

### 1. Logger Interface Changes

The logging system has been completely refactored to support structured logging:

```go
// OLD (pre-v2.0.0)
s.Logger.Info("Connected to database", dbName)

// NEW (v2.0.0+)
s.Logger.Info("Connected to database", F("name", dbName))
```

All logger methods now accept a message string and a variable number of `LogField` objects. Use the `F()` helper function to create these fields.

### 2. MongoDB Interface Changes

Database connections no longer panic on failure and return more information:

```go
// OLD (pre-v2.0.0)
client := EpicServerDb.GetMongoClient(s, "default")
collection := client.Database("myapp").Collection("users")

// NEW (v2.0.0+)
client, ok := EpicServerDb.GetMongoClient(s, "default")
if !ok {
    // Handle error
    return
}
collection, err := EpicServerDb.GetMongoCollection(s, "default", "myapp", "users")
if err != nil {
    // Handle error
    return
}
```

### 3. Server Initialization Error Handling

Server initialization now captures errors instead of panicking:

```go
// OLD (pre-v2.0.0)
server := EpicServer.NewServer([]EpicServer.Option{
    EpicServer.SetSecretKey([]byte("your-secret-key")),
})
// If configuration is invalid, this would panic
server.Start()

// NEW (v2.0.0+)
server := EpicServer.NewServer([]EpicServer.Option{
    EpicServer.SetSecretKey([]byte("your-secret-key")),
})
if server.HasErrors() {
    for _, err := range server.GetErrors() {
        fmt.Printf("Server initialization error: %v\n", err)
    }
    return
}
server.Start()
```

### 4. Memory Cache Configuration

Memory cache now requires additional configuration parameters:

```go
// OLD (pre-v2.0.0)
s.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServerCache.WithMemoryCache(&EpicServerCache.MemoryCacheConfig{
        Name: "default",
        Type: "memory",
    }),
})

// NEW (v2.0.0+)
s.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServerCache.WithMemoryCache(&EpicServerCache.MemoryCacheConfig{
        Name: "default",
        Type: "memory",
        DefaultTTL: 5 * time.Minute,
        CleanupInterval: time.Minute,
        MaxItems: 1000, // Optional
    }),
})
```

## New Features Usage

### Environment Variables Configuration

```go
// Load configuration from environment variables
server := EpicServer.NewServer([]EpicServer.Option{
    EpicServer.WithEnvVars(),
    // Provide fallback values for critical settings
    EpicServer.SetSecretKey([]byte("fallback-secret-key")),
})
```

Available environment variables:
- `EPICSERVER_SERVER_HOST`: Server host
- `EPICSERVER_SERVER_PORT`: Server port
- `EPICSERVER_SERVER_ENVIRONMENT`: Environment name
- `EPICSERVER_SECURITY_SECURECOOKIE`: Enable secure cookies (true/false)
- `EPICSERVER_SECURITY_COOKIEDOMAIN`: Cookie domain
- `EPICSERVER_SECURITY_CSPHEADER`: Content Security Policy header
- `EPICSERVER_SECURITY_ORIGINS`: Comma-separated CORS origins
- `EPICSERVER_SECRETKEY`: Secret key for encryption/signing

### Rate Limiting

```go
// Add rate limiting to your server
import (
    "time"
    
    "github.com/tomskip123/EpicServer/v2"
)

// Later in your code:
s.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithRateLimiter(EpicServer.RateLimiterConfig{
        MaxRequests: 100,
        Interval: time.Minute,
        BlockDuration: 5 * time.Minute,
        ExcludedPaths: []string{"/health", "/static/*"},
    }),
})
```

### Security Headers

```go
// Add recommended security headers to all responses
s.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithSecurityHeaders(nil), // Use defaults
})

// Or with custom configuration
s.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithSecurityHeaders(&EpicServer.SecurityHeadersConfig{
        EnableHSTS: true,
        HSTSMaxAge: 63072000, // 2 years
        ContentSecurityPolicy: "default-src 'self'",
    }),
})
```

### Structured Logging Configuration

```go
// Configure log level
s.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithLogLevel(EpicServer.LogLevelDebug),
})

// Configure log format
s.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithLogFormat(EpicServer.LogFormatJSON),
})

// Log with structured fields
s.Logger.Info("User authenticated", 
    EpicServer.F("user_id", userID), 
    EpicServer.F("ip", ip),
    EpicServer.F("duration_ms", authDuration.Milliseconds()))
```

### Module-Based Logging (v2.0.2+)

EpicServer v2.0.2 introduces module-based logging, allowing you to control log levels for specific components of your application:

```go
// Set log level for specific modules
s.UpdateAppLayer([]EpicServer.AppLayer{
    // Set global default log level
    EpicServer.WithLogLevel(EpicServer.LogLevelInfo),
    
    // Enable debug logging only for authentication-related code
    EpicServer.WithModuleLogLevel("auth", EpicServer.LogLevelDebug),
    
    // Set error-only logging for database operations
    EpicServer.WithModuleLogLevel("db", EpicServer.LogLevelError),
})

// Create module-specific loggers in your code
authLogger := s.Logger.WithModule("auth")
dbLogger := s.Logger.WithModule("db")

// These logs will respect their module's log level
authLogger.Debug("OAuth flow started") // Will be logged (auth module is at Debug level)
dbLogger.Debug("Connection pool stats") // Won't be logged (db module is at Error level)
dbLogger.Error("Database connection failed") // Will be logged

// You can also use hierarchical module names
authOAuthLogger := s.Logger.WithModule("auth.oauth")
authBasicLogger := s.Logger.WithModule("auth.basic")

// These will inherit from parent modules if no specific level is set
// In this case, both inherit LogLevelDebug from the "auth" module
```

Module-based logging features:

- **Hierarchical modules**: Use dot notation (e.g., `auth.oauth`) to create a hierarchy of modules
- **Inheritance**: Modules inherit log levels from parent modules if not explicitly set
- **Global registry**: Module log levels are stored in a global registry by default
- **Custom registries**: Create isolated log level registries for more complex applications

Advanced usage with custom registry:

```go
// Create a custom log registry
registry := EpicServer.NewLogRegistry(EpicServer.LogLevelWarn)
registry.SetLevel("api", EpicServer.LogLevelDebug)

// Use the custom registry
s.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithLogRegistry(registry),
})

// Or create a logger with a custom registry directly
logger := EpicServer.NewLoggerWithRegistry(os.Stdout, EpicServer.LogLevelInfo, EpicServer.LogFormatText, registry)
``` 