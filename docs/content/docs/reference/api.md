---
title: "API Reference"
description: "Complete API reference for EpicServer."
summary: "Detailed documentation of all EpicServer's public API methods and types."
date: 2023-09-07T16:06:50+02:00
lastmod: 2023-09-07T16:06:50+02:00
draft: false
weight: 10
toc: true
seo:
  title: "EpicServer API Reference" # custom title (optional)
  description: "Complete API reference for all EpicServer's public methods, types, and interfaces." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Server Options

* `WithHealthCheck(path string)` - Adds a health check endpoint
* `WithCompression()` - Enables response compression
* `WithRemoveWWW()` - Removes www prefix from domain
* `WithCors(origins []string)` - Configures CORS settings
* `WithEnvironment(environment string)` - Sets runtime environment (development/production/test)
* `WithTrustedProxies(proxies []string)` - Configures trusted proxy addresses
* `WithHttp2()` - Enables HTTP/2 support

## Configuration System

EpicServer provides a flexible configuration system using options pattern.

### Basic Configuration

```go
package main

import (
    "github.com/tomskip123/EpicServer/v2"
)

func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetHost("localhost", 8080),
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })
}
```

### Available Configuration Options

The `Config` struct supports the following configurations:

```go
type Config struct {
    Server struct {
        Host        string
        Port        int
        Environment string
    }
    Security struct {
        SecureCookie bool
        CookieDomain string
        CSPHeader    string
        Origins      []string
    }
    SecretKey []byte
    Custom    interface{}
}
```

### Setting Server Options

Configure server host and port:

```go
EpicServer.SetHost("0.0.0.0", 3000)
```

### Setting Security Options

Configure secret key for encryption:

```go
EpicServer.SetSecretKey([]byte("32-byte-long-secret-key-here...."))
```

## Database Methods

MongoDB specific helpers:
* `StringToObjectID(id string)` - Convert string to MongoDB ObjectID
* `StringArrayToObjectIDArray(ids []string)` - Convert string array to ObjectID array
* `UpdateIndexes(ctx, collection, indexes)` - Create or update collection indexes
* `StringArrayContains(array []string, value string)` - Check if string array contains value

GORM specific helpers:
* `AutoMigrateModels(s *EpicServer.Server, connectionName string, models ...interface{}) error` - Run GORM AutoMigrate for the given models

## Cache Methods

* `Set(key string, value interface{}, duration time.Duration)` - Store a value with expiration
* `Get(key string) (interface{}, bool)` - Retrieve a value if it exists
* `Delete(key string)` - Remove a value from the cache

## Authentication Methods

* `GenerateCSRFToken() (string, error)` - Generate a CSRF token
* `IsTrustedSource(req *http.Request) bool` - Validate CSRF token
* `GetSession(c *gin.Context) (*Session, error)` - Retrieve session data

## Logging System

* `Info(message string, args ...interface{})` - Logs an informational message
* `Warn(message string, args ...interface{})` - Logs a warning message
* `Error(message string, args ...interface{})` - Logs an error message

## Structured Logging Configuration

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

## Module-Based Logging (v2.0.2+)

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