# EpicServer

> A powerful, flexible, and production-ready Go web server built on top of Gin framework.

![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.23-blue)
![Version](https://img.shields.io/badge/version-2.0.4-blue)
[![Coverage Status](https://coveralls.io/repos/github/tomskip123/EpicServer/badge.svg?branch=main&v=1)](https://coveralls.io/github/tomskip123/EpicServer?branch=main&v=1)

**[💻 GitHub Repo](https://github.com/tomskip123/EpicServer)**

## ⚠️ Breaking Changes in v2.0.0

Version 2.0.0 introduces significant improvements with breaking changes. See [CHANGELOG.md](CHANGELOG.md) for details and migration guide.

Key changes:
- Structured logging replaces variadic logging
- Database connections now return errors instead of panicking
- Enhanced configuration system with validation
- Improved security features

## 📝 Enhanced Documentation in v2.0.1

Version 2.0.1 improves documentation with:
- Detailed migration guide with code examples
- Comprehensive API usage examples
- Improved integration examples with imports and context
- Enhanced changelog maintenance

## 📊 Enhanced Logging in v2.0.2

Version 2.0.2 introduces a powerful module-based logging system:
- Hierarchical module structure with inheritance (e.g., `auth.oauth`)
- Global log level registry for centralized management
- Custom log registries for complex applications
- New methods: `WithModule()`, `SetRegistry()`, and global helpers
- New AppLayers: `WithModuleLogLevel()` and `WithLogRegistry()`

## 🧪 Enhanced Test Coverage in v2.0.3

Version 2.0.3 improves test coverage and reliability:
- Improved overall test coverage to 80.7%, surpassing the minimum threshold of 80%
- Added comprehensive tests for CSRF protection functionality
- Enhanced logging test suite with additional test cases
- Fixed edge cases in authentication tests
- Added specific tests for middleware components

## 🔄 Documentation Updates in v2.0.4

- **Comprehensive Documentation**:
  - Added detailed documentation for HTTP/2 support functionality
  - Added documentation for Trusted Proxies configuration features
  - Expanded Rate Limiting documentation with configuration examples
  - Added comprehensive Advanced Logging Configuration section
  - Improved Static File Serving documentation including SPA support

## 🔧 Recent Improvements in v2.0.3

- **Thread Safety Improvements**:
  - Fixed data race condition in Server struct by adding a mutex to protect concurrent access
  - Updated `Start()` and `Stop()` methods to use mutex protection when accessing the HTTP server
  - Enhanced tests to properly handle concurrent access to server resources

## Table of Contents

1. [Getting Started](#getting-started)
   - [Installation](#installation)
   - [Quick Start](#quick-start)
   - [Basic Example](#basic-example)

2. [Core Features](#core-features)
   - [Configuration System](#configuration-system)
   - [Routing](#routing)
   - [Authentication](#authentication)
   - [Database Support](#database-support)
   - [Caching](#caching)
   - [Static File Serving](#static-file-serving)
   - [Middleware](#middleware)

3. [Advanced Usage](#advanced-usage)
   - [Custom Configuration](#custom-configuration)
   - [Multiple Database Connections](#multiple-database-connections)
   - [Authentication Hooks](#authentication-hooks)
   - [Custom Middleware](#custom-middleware)
   - [SPA Support](#spa-support)
   - [Test Coverage](#test-coverage)

4. [Security](#security)
   - [Authentication Setup](#authentication-setup)
   - [CSRF Protection](#csrf-protection)
   - [Security Headers](#security-headers)
   - [Environment Variables](#environment-variables)
   - [Rate Limiting](#rate-limiting)

5. [API Reference](#api-reference)
   - [Server Options](#server-options)
   - [Database Methods](#database-methods)
   - [Cache Methods](#cache-methods)
   - [Authentication Methods](#authentication-methods)
   - [Logging System](#logging-system)

6. [Migration Guide](#migration-guide)
   - [Upgrading to v2.0.0](#upgrading-to-v200)
   - [Structured Logging](#structured-logging)
   - [Error Handling](#error-handling)

7. [Contributing](#contributing)
   - [Getting Started](#getting-started-1)
   - [Development](#development)
   - [Testing Your Changes](#testing-your-changes)
   - [Submitting Changes](#submitting-changes)
   - [Code Style](#code-style)

8. [Changelog](#changelog)

9. [License](#license)
10. [Support](#support)

## Getting Started

### Installation

```bash
go get github.com/tomskip123/EpicServer/v2
```

> **Note:** Version 2.x is the only supported version. Version 1.x is deprecated and should not be used for new projects.

### Quick Start

Create a new web server in just a few lines:

```go
package main

import "github.com/tomskip123/EpicServer/v2"

func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })

    server.UpdateAppLayer([]EpicServer.AppLayer{
        EpicServer.WithHealthCheck("/health"),
        EpicServer.WithEnvironment("development"),
    })

    server.Start()
}
```

### Basic Example

Here's a complete example with routing, database, and authentication:

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/gin-gonic/gin"
    "github.com/tomskip123/EpicServer/v2"
    "github.com/tomskip123/EpicServer/v2/db"
)

func main() {
    // Create a new server with options
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetHost("localhost", 8080),
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })
    
    // Check for initialization errors
    if server.HasErrors() {
        for _, err := range server.GetErrors() {
            log.Fatalf("Server initialization error: %v", err)
        }
    }

    // Add application layers
    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Add routes
        EpicServer.WithRoutes(
            EpicServer.RouteGroup{
                Prefix: "/api/v1",
                Routes: []EpicServer.Route{
                    EpicServer.Get("/users", HandleUsers),
                },
            },
        ),
        // Add MongoDB connection
        EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
            ConnectionName: "default",
            URI:           "mongodb://localhost:27017",
            DatabaseName:  "myapp",
        }),
        // Add logging middleware
        EpicServer.WithLoggerMiddleware(),
        // Add security headers
        EpicServer.WithSecurityHeaders(&EpicServer.SecurityHeadersConfig{
            EnableHSTS:               true,
            EnableContentTypeOptions: true,
            EnableFrameOptions:       true,
            FrameOption:              "DENY",
            EnableXSSProtection:      true,
        }),
    })

    // Start the server
    if err := server.Start(); err != nil {
        log.Fatalf("Server error: %v", err)
    }
}

func HandleUsers(c *gin.Context, s *EpicServer.Server) {
    // Get MongoDB client
    client, ok := EpicServerDb.GetMongoClient(s, "default")
    if !ok {
        c.JSON(500, gin.H{"error": "MongoDB client not found"})
        return
    }
    
    // Use the client
    db := client.Database("myapp")
    collection := db.Collection("users")
    
    // Log with module-based logging
    logger := s.Logger.WithModule("api.users")
    logger.Info("Handling users request", EpicServer.F("path", c.Request.URL.Path))
    
    // Handle request
    c.JSON(200, gin.H{"message": "users endpoint"})
}

## Core Features

### Configuration System

EpicServer provides a flexible configuration system using options pattern.

#### Basic Configuration

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

#### Available Configuration Options

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

#### Setting Server Options

Configure server host and port:

```go
EpicServer.SetHost("0.0.0.0", 3000)
```

#### Setting Security Options

Configure secret key for encryption:

```go
EpicServer.SetSecretKey([]byte("32-byte-long-secret-key-here...."))
```

### Routing

EpicServer provides a flexible routing system that allows you to organize your routes into groups and access server instance in your handlers.

#### Basic Route Setup

```go
package main

import (
    "github.com/tomskip123/EpicServer/v2"
)

func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })

    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Configure routes
        EpicServer.WithRoutes(
            EpicServer.RouteGroup{
                Prefix: "/api/v1",
                Routes: []EpicServer.Route{
                    EpicServer.Get("/users", HandleGetUsers),
                    EpicServer.Post("/users", HandleCreateUser),
                    EpicServer.Put("/users/:id", HandleUpdateUser),
                    EpicServer.Delete("/users/:id", HandleDeleteUser),
                },
            },
            EpicServer.RouteGroup{
                Prefix: "/admin",
                Routes: []EpicServer.Route{
                    EpicServer.Get("/stats", HandleAdminStats),
                },
            },
        ),
    })

    server.Start()
}
```

#### Route Handlers

Route handlers have access to both the Gin context and the server instance:

```go
func HandleGetUsers(c *gin.Context, s *EpicServer.Server) {
    // Access server components
    db := EpicServerDb.GetMongoClient(s, "default")
    cache := EpicServerCache.GetMemoryCache(s, "myCache")
    
    // Use gin context as normal
    userId := c.Param("id")
    query := c.Query("filter")
    
    // Send response
    c.JSON(200, gin.H{"message": "success"})
}
```

#### Available Route Methods

* `Get(path string, handler HandlerFunc)` - HTTP GET
* `Post(path string, handler HandlerFunc)` - HTTP POST
* `Put(path string, handler HandlerFunc)` - HTTP PUT
* `Patch(path string, handler HandlerFunc)` - HTTP PATCH
* `Delete(path string, handler HandlerFunc)` - HTTP DELETE

#### Route Groups

Group related routes with common prefix:

```go
EpicServer.WithRoutes(
    EpicServer.RouteGroup{
        Prefix: "/api/v1",
        Routes: []EpicServer.Route{
            // All routes here will be prefixed with /api/v1
        },
    },
)
```

#### Accessing Server Components

Route handlers can access all server components:

```go
func MyHandler(c *gin.Context, s *EpicServer.Server) {
    // Access configuration
    port := s.Config.Server.Port
    
    // Access logger
    s.Logger.Info("Handling request")
    
    // Access authentication
    session, _ := EpicServer.GetSession(c)
    
    // Access databases
    mongoClient := EpicServerDb.GetMongoClient(s, "mongodb")
    postgresDB := EpicServerDb.GetPostgresDB(s, "postgres")
    
    // Access cache
    cache := EpicServerCache.GetMemoryCache(s, "mycache")
    
    // Access hooks
    s.Hooks.Auth.OnUserCreate(claims)
}
```

### Authentication

EpicServer provides a flexible authentication system supporting multiple providers and custom authentication hooks.

#### Setting Up Authentication

```go
package main

import (
    "time"
    "github.com/tomskip123/EpicServer/v2"
)

func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })
    
    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Configure authentication
        EpicServer.WithAuth([]EpicServer.Provider{
            {
                Name:         "google",
                ClientId:     "your-client-id",
                ClientSecret: "your-client-secret",
                Callback:     "http://localhost:3000/auth/google/callback",
            },
        }, &EpicServer.SessionConfig{
            CookieName:      "auth_session",
            CookieDomain:    "localhost",
            CookieSecure:    false,
            CookieHTTPOnly:  true,
            SessionDuration: time.Hour * 24,
        }),
        // Add authentication middleware
        EpicServer.WithAuthMiddleware(EpicServer.SessionConfig{
            CookieName:   "auth_session",
            CookieDomain: "localhost",
            CookieSecure: false,
        }),
    })

    server.Start()
}
```

#### Configuring Public Paths

Define paths that don't require authentication:

```go
EpicServer.WithPublicPaths(EpicServer.PublicPathConfig{
    Exact: []string{
        "/health",
        "/login",
    },
    Prefix: []string{
        "/public",
        "/api/v1/public",
    },
})
```

#### Custom Authentication Hooks

Implement custom authentication logic:

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

// Add auth hooks to server
server.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithAuthHooks(&MyAuthHooks{db: db}),
})
```

#### Available Auth Providers

* Google (`"google"`)
* Basic Auth (`"basic"`)
* Custom providers can be added by implementing the provider interface

#### Environment Variables

Required environment variables for secure authentication:

```env
SECURE_COOKIE_HASH_KEY=base64_encoded_32_byte_key
SECURE_COOKIE_BLOCK_KEY=base64_encoded_32_byte_key
ENCRYPTION_KEY=32_byte_hex_encoded_key
```

Generate secure keys using:

```go
hashKey, _ := EpicServer.GenerateEncryptionKey()
blockKey, _ := EpicServer.GenerateEncryptionKey()
```

#### Authentication Endpoints

The following endpoints are automatically created:

* `/auth/:provider` - Initiates authentication flow
* `/auth/:provider/callback` - OAuth callback URL
* `/auth/logout` - Handles user logout

#### Session Management

Access session data in your handlers:

```go
func MyProtectedHandler(c *gin.Context) {
    session, err := EpicServer.GetSession(c)
    if err != nil {
        c.AbortWithStatus(401)
        return
    }
    
    // Access session data
    userEmail := session.Email
    userData := session.User
}
```

### Database Support

EpicServer supports multiple database adapters out of the box:

#### MongoDB

```go
package main

import (
    "github.com/tomskip123/EpicServer/v2"
    "github.com/tomskip123/EpicServer/db"
)

func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })

    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Configure MongoDB
        EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
            ConnectionName: "default",
            URI:           "mongodb://localhost:27017",
            DatabaseName:  "myapp",
        }),
    })

    server.Start()
}

func HandleUsers(c *gin.Context, s *EpicServer.Server) {
    client := EpicServerDb.GetMongoClient(s, "default")
    db := client.Database("myapp")
    collection := db.Collection("users")
    // Handle request using MongoDB...
}
```

#### PostgreSQL

```go
package main

import (
    "github.com/tomskip123/EpicServer/v2"
    "github.com/tomskip123/EpicServer/db"
)

func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })

    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Configure PostgreSQL
        EpicServerDb.WithPostgres(EpicServerDb.PostgresConfig{
            ConnectionName: "default",
            Host:          "localhost",
            Port:          5432,
            User:          "postgres",
            Password:      "password",
            Database:      "myapp",
            SSLMode:       "disable",
        }),
    })

    server.Start()
}

func HandleUsers(c *gin.Context, s *EpicServer.Server) {
    db := EpicServerDb.GetPostgresDB(s, "default")
    // Handle request using PostgreSQL...
}
```

#### MySQL

```go
package main

import (
    "github.com/tomskip123/EpicServer/v2"
    "github.com/tomskip123/EpicServer/db"
)

func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })

    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Configure MySQL
        EpicServerDb.WithMySQL(EpicServerDb.MySQLConfig{
            ConnectionName: "default",
            Host:          "localhost",
            Port:          3306,
            User:          "root",
            Password:      "password",
            Database:      "myapp",
        }),
    })

    server.Start()
}

func HandleUsers(c *gin.Context, s *EpicServer.Server) {
    db := EpicServerDb.GetMySQLDB(s, "default")
    // Handle request using MySQL...
}
```

#### GORM

```go
package main

import (
	"github.com/tomskip123/EpicServer/v2"
	"github.com/tomskip123/EpicServer/db"
)

func main() {
	server := EpicServer.NewServer([]EpicServer.Option{
		EpicServer.SetSecretKey([]byte("your-secret-key")),
	})

	server.UpdateAppLayer([]EpicServer.AppLayer{
		// Configure GORM
		EpicServerDb.WithGorm(&EpicServerDb.GormConfig{
			ConnectionName: "default",
			Dialect:        "mysql", // "mysql", "postgres", or "sqlite"
			DSN:            "user:password@tcp(localhost:3306)/dbname",
		}),
	})

	server.Start()
}

func HandleUsers(c *gin.Context, s *EpicServer.Server) {
	db := EpicServerDb.GetGormDB(s, "default")
	// Handle request using GORM...
}
```

### Caching

EpicServer includes a built-in memory cache system for temporary data storage.

#### Setting Up Memory Cache

```go
package main

import (
    "github.com/tomskip123/EpicServer/v2"
    "github.com/tomskip123/EpicServer/cache"
)

func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })

    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Configure memory cache
        EpicServerCache.WithMemoryCache(&EpicServerCache.MemoryCacheConfig{
            Name: "myCache",
            Type: "memory",
        }),
    })

    server.Start()
}
```

#### Using the Cache

The cache provides simple key-value storage with expiration:

```go
func MyHandler(c *gin.Context) {
    cache := EpicServerCache.GetMemoryCache(server, "myCache")
    
    // Set cache item with 5-minute expiration
    cache.Set("myKey", "myValue", 5*time.Minute)
    
    // Get cache item
    value, exists := cache.Get("myKey")
    if exists {
        // Use cached value
    }
    
    // Delete cache item
    cache.Delete("myKey")
}
```

#### Cache Features

* In-memory key-value storage
* Automatic expiration of cached items
* Thread-safe operations
* Zero configuration required for memory cache
* Multiple named cache instances

#### Cache Methods

* `Set(key string, value interface{}, duration time.Duration)` - Store a value with expiration
* `Get(key string) (interface{}, bool)` - Retrieve a value if it exists
* `Delete(key string)` - Remove a value from the cache

### Static File Serving

EpicServer provides efficient static file serving with support for embedded files.

#### Basic Static File Serving

Serve static files from a directory:

```go
//go:embed static/*
var staticFiles embed.FS

func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })

    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Serve static files
        EpicServer.WithStaticDirectory("/static", &staticFiles, "static"),
    })

    server.Start()
}
```

#### Custom MIME Types

Serve specific static files with custom MIME types:

```go
//go:embed favicon.ico
var favicon embed.FS

func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })

    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Serve a single static file
        EpicServer.WithStaticFile(
            "favicon.ico",           // URL path
            &favicon,                // Embedded filesystem
            "favicon.ico",           // File path in embedded filesystem
            "image/x-icon",          // MIME type
        ),
    })

    server.Start()
}
```

#### SPA Support

Configure the server to handle SPA routing:

```go
//go:embed dist/*
var spaFiles embed.FS

func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })
    
    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Configure SPA handling
        EpicServer.WithSPACatchAll(
            &spaFiles,              // Embedded filesystem
            "dist",                 // Static files directory
            "dist/index.html",      // SPA entry point
        ),
    })
    
    server.Start()
}
```

#### Static File Features

* Embedded file system support using Go 1.16+ `embed` package
* Automatic MIME type detection
* Custom MIME type configuration
* SPA route fallback support
* Directory listing prevention
* Efficient file serving

#### Static File Configuration

The static file system supports:

* Multiple static directories
* Mixed static files and API routes
* Custom 404 handling
* Secure file serving
* File type restrictions
* Path normalization

#### Example with Multiple Static Configurations

```go
//go:embed assets/* spa/* favicon.ico
var files embed.FS

func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })

    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Serve static assets
        EpicServer.WithStaticDirectory("/assets", &files, "assets"),
        
        // Serve favicon
        EpicServer.WithStaticFile("favicon.ico", &files, "favicon.ico", "image/x-icon"),
        
        // Configure SPA
        EpicServer.WithSPACatchAll(&files, "spa", "spa/index.html"),
    })

    server.Start()
}
```

### Middleware

EpicServer provides several built-in middleware options and supports custom middleware creation.

#### Compression Middleware

> ⚠️ **Important Note**: Compression middleware is **already included by default** in the server initialization. You do not need to add it manually with `WithCompression()`. Adding it again will result in the middleware being applied twice, which can cause issues.

If you need to customize compression settings, you can replace the default middleware with your own implementation.

```go
func main() {
    // DO NOT add compression middleware like this unless you have a specific reason
    // as it's already included by default:
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })
}
```

Default middleware layers included automatically:
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

Features:
* Automatic gzip compression
* Smart cache control headers
* Asset-specific caching rules
* Conditional compression based on Accept-Encoding

#### CORS Middleware

Configure Cross-Origin Resource Sharing:

```go
func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })

    server.UpdateAppLayer([]EpicServer.AppLayer{
        EpicServer.WithCors([]string{
            "https://example.com",
            "https://api.example.com",
        }),
    })

    server.Start()
}
```

Features:
* Origin validation
* Configurable allowed origins
* Preflight request handling
* Custom headers support
* Credential support

#### CSRF Protection

EpicServer provides built-in CSRF protection to prevent cross-site request forgery attacks.

```go
// Add CSRF protection to your server
server.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithCSRFProtection(EpicServer.CSRFConfig{
        CookieName:     "csrf_token",
        HeaderName:     "X-CSRF-Token",
        CookieMaxAge:   3600,
        CookieSecure:   true,
        CookieHTTPOnly: true,
        CookieSameSite: http.SameSiteStrictMode,
        ExcludedPaths:  []string{"/api/webhook", "/health"},
    }),
})
```

To use CSRF protection in your templates:

```html
<form method="POST" action="/submit">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <!-- other form fields -->
    <button type="submit">Submit</button>
</form>
```

For AJAX requests, include the CSRF token in the request headers:

```javascript
fetch('/api/data', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
    },
    body: JSON.stringify({ key: 'value' })
})
```

#### WWW Redirect Middleware

Automatically redirect www to non-www or vice versa:

```go
// Redirect www to non-www
server.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithRemoveWWW(),
})
```

Features:
* Automatic www detection
* Permanent redirects (301)
* HTTPS upgrade support
* Path preservation

#### Custom Middleware

Create your own middleware:

```go
func MyCustomMiddleware() AppLayer {
    return func(s *EpicServer.Server) {
        s.Engine.Use(func(c *gin.Context) {
            // Pre-processing
            c.Set("custom_key", "custom_value")
            
            c.Next()
            
            // Post-processing
            status := c.Writer.Status()
            if status >= 500 {
                s.Logger.Error("Server error occurred", EpicServer.F("status", status))
            }
        })
    }
}

// Usage
server := EpicServer.NewServer([]EpicServer.Option{
    EpicServer.SetSecretKey([]byte("your-secret-key")),
})

server.UpdateAppLayer([]EpicServer.AppLayer{
    MyCustomMiddleware(),
})
```

#### Middleware Order

Middleware is executed in the order it's added. Be aware that some middleware is already included by default (as shown in the Compression Middleware section).

```go
// Default middleware is applied first in this order:
// 1. WithLoggerMiddleware()
// 2. WithHealthCheck("/health")
// 3. WithCompression()
// 4. WithRemoveWWW()
// 5. WithEnvironment(config.Server.Environment)

// Then your custom middleware is applied:
server := EpicServer.NewServer([]EpicServer.Option{
    EpicServer.SetSecretKey([]byte("your-secret-key")),
})

server.UpdateAppLayer([]EpicServer.AppLayer{
    // DO NOT add middleware that's already included by default
    // EpicServer.WithCompression(),    // WRONG: Already included by default
    
    // DO add custom middleware you need
    EpicServer.WithCors(origins),    // This will be 6th in execution order
    MyCustomMiddleware(),            // This will be 7th in execution order
})
```

When adding your own middleware, remember that it will be executed after the default middleware. If you need to replace or customize default middleware, you should use a different approach (see Custom Configuration section).

#### Built-in Security Headers

All responses automatically include security headers:
* X-Content-Type-Options: nosniff
* X-Frame-Options: DENY
* X-XSS-Protection: 1; mode=block
* Strict-Transport-Security: max-age=31536000; includeSubDomains
* Content-Security-Policy: configurable

#### HTTP/2 Support

Enable HTTP/2 for improved performance:

```go
server.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithHttp2(),
})
```

Features:
* HTTP/2 multiplexing for parallel requests
* Header compression
* Server push capabilities
* Reduced latency
* Backward compatible

#### Trusted Proxies Configuration

When running behind load balancers, CDNs, or reverse proxies:

```go
server.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithTrustedProxies([]string{
        "127.0.0.1",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    }),
})
```

Features:
* Proper handling of X-Forwarded-* headers
* Correct client IP detection
* Support for both individual IPs and CIDR ranges
* Enhanced security for proxy environments

#### Rate Limiting

Protect your server from abuse with rate limiting:

```go
server.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithRateLimiter(EpicServer.RateLimiterConfig{
        MaxRequests:   100,             // Maximum requests per interval
        Interval:      time.Minute,     // Time window for request counting
        BlockDuration: 5 * time.Minute, // How long to block after exceeding limit
        ExcludedPaths: []string{        // Paths to exclude from rate limiting
            "/health",
            "/api/webhook",
            "/public/*",
        },
    }),
})
```

Features:
* IP-based rate limiting
* Configurable request thresholds
* Automatic blocking of abusive clients
* Path-based exclusions
* Appropriate HTTP headers (X-RateLimit-*)
* Cleanup of expired blocks

#### Advanced Logging Configuration

EpicServer provides extensive logging configuration options to tailor the logging system to your needs:

```go
server.UpdateAppLayer([]EpicServer.AppLayer{
    // Set global log level
    EpicServer.WithLogLevel(EpicServer.LogLevelDebug),
    
    // Configure log format (JSON or Text)
    EpicServer.WithLogFormat(EpicServer.LogFormatJSON),
    
    // Set log level for specific modules
    EpicServer.WithModuleLogLevel("auth", EpicServer.LogLevelDebug),
    EpicServer.WithModuleLogLevel("db", EpicServer.LogLevelInfo),
    
    // Or use a custom log registry for more control
    EpicServer.WithLogRegistry(customRegistry),
    
    // Use a completely custom logger implementation
    EpicServer.WithCustomLogger(myCustomLogger),
})
```

Features:
* Module-based log levels for granular control
* JSON or text output formats
* Custom log registry for centralized level management
* Support for custom logger implementations
* Contextual logging with fields
* Performance optimized

#### Static File Serving

Serve static files and single-page applications (SPAs) with ease:

```go
//go:embed static
var staticFiles embed.FS

server.UpdateAppLayer([]EpicServer.AppLayer{
    // Serve a directory of static files
    EpicServer.WithStaticDirectory("/static", &staticFiles, "static"),
    
    // Serve individual files with custom MIME types
    EpicServer.WithStaticFile("/favicon.ico", &staticFiles, "static/favicon.ico", "image/x-icon"),
    
    // Handle SPA routing (serve index.html for non-matched routes)
    EpicServer.WithSPACatchAll(&staticFiles, "static", "static/index.html"),
})
```

Features:
* Embedded file system support via Go 1.16+ embed package
* Directory and individual file serving
* Custom MIME type configuration
* Single-page application (SPA) support with catch-all routes
* Efficient file serving with proper caching headers

## Advanced Usage

### Custom Configuration

Add your own configuration values:

```go
type MyCustomConfig struct {
    APIKey      string
    MaxRequests int
    Features    []string
}

customConfig := MyCustomConfig{
    APIKey:      "my-api-key",
    MaxRequests: 1000,
    Features:    []string{"feature1", "feature2"},
}

server := EpicServer.NewServer([]EpicServer.Option{
    EpicServer.SetCustomConfig(customConfig),
})

// Access custom config in handlers
func MyHandler(c *gin.Context, s *EpicServer.Server) {
    config := EpicServer.GetCustomConfig(s).(MyCustomConfig)
    apiKey := config.APIKey
    // Use configuration...
}

#### Replacing Default Middleware

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

#### Specifying Your Own Default Layers

If you want to completely customize the default layers while still using the standard server initialization flow, you can create a wrapper function around `NewServer`:

```go
// Create a function that initializes a server with your custom default layers
func NewCustomServer(options []EpicServer.Option) *EpicServer.Server {
    // Initialize the server with default configuration
    config := EpicServer.defaultConfig()

    // Apply options to modify the configuration
    for _, opt := range options {
        opt(config)
    }

    // Validate configuration
    if err := config.Validate(); err != nil {
        s := &EpicServer.Server{
            Config: config,
            errors: []error{err},
        }
        return s
    }

    // Initialize Gin engine
    engine := gin.New()

    s := &EpicServer.Server{
        Config:      config,
        Engine:      engine,
        PublicPaths: make(map[string]bool),
        AuthConfigs: make(map[string]*EpicServer.Auth),
        Db:          make(map[string]interface{}),
        Cache:       make(map[string]interface{}),
        errors:      make([]error, 0),
    }

    // Initialize the logger
    s.Logger = EpicServer.defaultLogger(os.Stdout)

    // Setup default hooks
    s.Hooks = EpicServer.defaultHooks(s)

    // Setup YOUR custom default layers
    myDefaultLayers := []EpicServer.AppLayer{
        EpicServer.WithLoggerMiddleware(), // Usually keep this first
        EpicServer.WithHealthCheck("/custom-health"), // Customize health check path
        // Skip compression if you don't want it
        // EpicServer.WithCompression(),
        // Add your own custom middleware
        MyCustomMiddleware(),
        // Keep other default middleware you want
        EpicServer.WithRemoveWWW(),
        EpicServer.WithEnvironment(config.Server.Environment),
    }

    // Apply your custom default layers
    for _, layer := range myDefaultLayers {
        layer(s)
    }

    return s
}

// Usage
func main() {
    server := NewCustomServer([]EpicServer.Option{
        EpicServer.SetHost("localhost", 8080),
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })

    // Add additional app layers if needed
    server.UpdateAppLayer([]EpicServer.AppLayer{
        EpicServer.WithCors([]string{"https://example.com"}),
    })

    server.Start()
}
```

This approach allows you to:
1. Completely customize which default layers are included
2. Change the order of default layers
3. Add your own custom middleware as part of the default layers
4. Still use the standard server configuration options

### Multiple Database Connections

You can configure multiple database connections with different connection names:

```go
server := EpicServer.NewServer([]EpicServer.Option{
    EpicServer.SetSecretKey([]byte("your-secret-key")),
})

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
        // ...other config
    }),
    EpicServerDb.WithMySQL(EpicServerDb.MySQLConfig{
        ConnectionName: "orders",
        Host:          "localhost",
        Database:      "orders",
        // ...other config
    }),
})
```

### Authentication Hooks

Implement custom authentication logic:

```go
type MyAuthHooks struct {
    db *Database
}

```

### Test Coverage

EpicServer maintains high test coverage standards to ensure reliability and stability.

#### Running Test Coverage Analysis

To run tests and generate a coverage report:

```bash
# Run the test coverage script
./test-coverage.sh

# Run with options to exclude test helpers (default behavior)
./test-coverage.sh

# Run without failing on coverage threshold
./test-coverage.sh --no-fail

# Run including test helpers in coverage calculation
./test-coverage.sh --include-test-helpers

# Combine options
./test-coverage.sh --no-fail --include-test-helpers
```

The coverage report will be generated in the `coverage` directory. The HTML report provides detailed information about which code paths are covered by tests and which need additional testing.

#### Script Options

- `--no-fail`: Prevents the script from returning a non-zero exit code when coverage is below the threshold
- `--include-test-helpers`: Includes test helper files in the coverage calculation (by default, test helpers are excluded)

#### Coverage Requirements

- Minimum coverage threshold: 80%
- Critical components require 90%+ coverage:
  - Authentication mechanisms
  - Database connectivity
  - Core server initialization

#### Continuous Integration

The GitHub workflow automatically verifies test coverage on every pull request and push to the main branch, ensuring that coverage standards are maintained throughout development.

To contribute code to EpicServer:
1. Write tests for any new functionality
2. Ensure existing tests pass and coverage meets or exceeds thresholds
3. Run `./test-coverage.sh` locally before submitting a pull request

#### Server Initialization Errors

```go
// Create a new server instance
server := EpicServer.NewServer([]EpicServer.Option{
    EpicServer.SetSecretKey([]byte("your-secret-key")),
})

// Check for initialization errors
if server.HasErrors() {
    for _, err := range server.GetErrors() {
        fmt.Printf("Server initialization error: %v\n", err)
    }
    return
}

// Proceed with server configuration
server.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithHealthCheck("/health"),
})

// Start the server
if err := server.Start(); err != nil {
    fmt.Printf("Server start error: %v\n", err)
    return
}
```

#### Database Connection Errors

```go
// Get MongoDB client with error checking
client, ok := EpicServerDb.GetMongoClient(s, "default")
if !ok {
    // Handle error
    c.JSON(500, gin.H{"error": "Database connection failed"})
    return
}

// Get MongoDB collection with error checking
collection, err := EpicServerDb.GetMongoCollection(s, "default", "myapp", "users")
if err != nil {
    // Handle error