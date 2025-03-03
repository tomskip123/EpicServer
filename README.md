# EpicServer

> A powerful, flexible, and production-ready Go web server built on top of Gin framework.

![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.16-blue)
![Version](https://img.shields.io/badge/version-2.0.1-blue)
[![Coverage Status](https://coveralls.io/repos/github/tomskip123/EpicServer/badge.svg?branch=main&v=1)](https://coveralls.io/github/tomskip123/EpicServer?branch=main&v=1)

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

See [CHANGELOG.md](CHANGELOG.md) for complete details.

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
go get github.com/tomskip123/EpicServer
```

### Quick Start

Create a new web server in just a few lines:

```go
package main

import "github.com/tomskip123/EpicServer"

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
    "github.com/gin-gonic/gin"
    "github.com/tomskip123/EpicServer"
    "github.com/tomskip123/EpicServer/db"
)

func main() {
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetHost("localhost", 8080),
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })

    server.UpdateAppLayer([]EpicServer.AppLayer{
        EpicServer.WithRoutes(
            EpicServer.RouteGroup{
                Prefix: "/api/v1",
                Routes: []EpicServer.Route{
                    EpicServer.Get("/users", HandleUsers),
                },
            },
        ),
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
    c.JSON(200, gin.H{"message": "users endpoint"})
}
```

## Core Features

### Configuration System

EpicServer provides a flexible configuration system using options pattern.

#### Basic Configuration

```go
package main

import (
    "github.com/tomskip123/EpicServer"
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
    "github.com/tomskip123/EpicServer"
)

func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
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
        },
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
    "github.com/tomskip123/EpicServer"
)

func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
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
        },
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
    "github.com/tomskip123/EpicServer"
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
    "github.com/tomskip123/EpicServer"
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
    "github.com/tomskip123/EpicServer"
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
	"github.com/tomskip123/EpicServer"
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
    "github.com/tomskip123/EpicServer"
    "github.com/tomskip123/EpicServer/cache"
)

func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // Configure memory cache
            EpicServerCache.WithMemoryCache(&EpicServerCache.MemoryCacheConfig{
                Name: "myCache",
                Type: "memory",
            }),
        },
    })

    // Use the cache in your handlers
    cache := EpicServerCache.GetMemoryCache(server, "myCache")
    
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
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // Serve static files
            EpicServer.WithStaticDirectory("/static", &staticFiles, "static"),
        },
    })
}
```

#### Custom MIME Types

Serve specific static files with custom MIME types:

```go
//go:embed favicon.ico
var favicon embed.FS

func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // Serve a single static file
            EpicServer.WithStaticFile(
                "favicon.ico",           // URL path
                &favicon,                // Embedded filesystem
                "favicon.ico",           // File path in embedded filesystem
                "image/x-icon",          // MIME type
            ),
        },
    })
}
```

#### SPA (Single Page Application) Support

Configure the server to handle SPA routing:

```go
//go:embed dist/*
var spaFiles embed.FS

func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // Configure SPA handling
            EpicServer.WithSPACatchAll(
                &spaFiles,              // Embedded filesystem
                "dist",                 // Static files directory
                "dist/index.html",      // SPA entry point
            ),
        },
    })
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
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // Serve static assets
            EpicServer.WithStaticDirectory("/assets", &files, "assets"),
            
            // Serve favicon
            EpicServer.WithStaticFile("favicon.ico", &files, "favicon.ico", "image/x-icon"),
            
            // Configure SPA
            EpicServer.WithSPACatchAll(&files, "spa", "spa/index.html"),
        },
    })
}
```

### Middleware

EpicServer provides several built-in middleware options and supports custom middleware creation.

#### Compression Middleware

Automatically compresses responses and sets appropriate cache headers:

```go
func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            EpicServer.WithCompression(),
        },
    })
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

#### CSRF Protection

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

#### WWW Redirect Middleware

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

#### Custom Middleware

Create your own middleware:

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

#### Middleware Order

Middleware is executed in the order it's added:

```go
server := EpicServer.NewServer(&EpicServer.NewServerParam{
    AppLayer: []EpicServer.AppLayer{
        EpicServer.WithCompression(),    // 1st
        EpicServer.WithCors(origins),    // 2nd
        EpicServer.WithRemoveWWW(),      // 3rd
        MyCustomMiddleware(),            // 4th
    },
})
```

#### Built-in Security Headers

All responses automatically include security headers:
* X-Content-Type-Options: nosniff
* X-Frame-Options: DENY
* X-XSS-Protection: 1; mode=block
* Strict-Transport-Security: max-age=31536000; includeSubDomains
* Content-Security-Policy: configurable

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

server := EpicServer.NewServer(&EpicServer.NewServerParam{
    Configs: []EpicServer.Option{
        EpicServer.SetCustomConfig(customConfig),
    },
})

// Access custom config in handlers
func MyHandler(c *gin.Context, s *EpicServer.Server) {
    config := EpicServer.GetCustomConfig(s).(MyCustomConfig)
    apiKey := config.APIKey
    // Use configuration...
}
```

### Multiple Database Connections

You can configure multiple database connections with different connection names:

```go
server := EpicServer.NewServer(&EpicServer.NewServerParam{
    AppLayer: []EpicServer.AppLayer{
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
    },
})
```

### Authentication Hooks

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

### Custom Middleware

Create your own middleware:

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

### SPA Support

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
}
```

### Test Coverage

EpicServer maintains high test coverage standards to ensure reliability and stability.

#### Running Test Coverage Analysis

To run tests and generate a coverage report:

```bash
# Run the test coverage script
./test-coverage.sh

# Or manually run coverage analysis
go test -race -coverprofile=./coverage/coverage.out -covermode=atomic ./...
go tool cover -html=./coverage/coverage.out -o ./coverage/coverage.html
```

The coverage report will be generated in the `coverage` directory. The HTML report provides detailed information about which code paths are covered by tests and which need additional testing.

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

## Security

### Authentication Setup

```go
package main

import (
    "github.com/tomskip123/EpicServer"
)

func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
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
        },
    })

    server.Start()
}
```

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

### Security Headers

All responses automatically include security headers:
* X-Content-Type-Options: nosniff
* X-Frame-Options: DENY
* X-XSS-Protection: 1; mode=block
* Strict-Transport-Security: max-age=31536000; includeSubDomains
* Content-Security-Policy: configurable

### Environment Variables

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

### Rate Limiting

EpicServer includes a built-in rate limiter to prevent abuse:

#### Setting Up Rate Limiting

```go
package main

import (
    "time"
    
    "github.com/tomskip123/EpicServer"
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

#### Rate Limiting Features

* Fixed window rate limiting
* Sliding window rate limiting
* Customizable duration
* Multiple named rate limiters

## API Reference

### Server Options

* `WithHealthCheck(path string)` - Adds a health check endpoint
* `WithCompression()` - Enables response compression
* `WithRemoveWWW()` - Removes www prefix from domain
* `WithCors(origins []string)` - Configures CORS settings
* `WithEnvironment(environment string)` - Sets runtime environment (development/production/test)
* `WithTrustedProxies(proxies []string)` - Configures trusted proxy addresses
* `WithHttp2()` - Enables HTTP/2 support

### Database Methods

MongoDB specific helpers:
* `StringToObjectID(id string)` - Convert string to MongoDB ObjectID
* `StringArrayToObjectIDArray(ids []string)` - Convert string array to ObjectID array
* `UpdateIndexes(ctx, collection, indexes)` - Create or update collection indexes
* `StringArrayContains(array []string, value string)` - Check if string array contains value

GORM specific helpers:
* `AutoMigrateModels(s *EpicServer.Server, connectionName string, models ...interface{}) error` - Run GORM AutoMigrate for the given models

### Cache Methods

* `Set(key string, value interface{}, duration time.Duration)` - Store a value with expiration
* `Get(key string) (interface{}, bool)` - Retrieve a value if it exists
* `Delete(key string)` - Remove a value from the cache

### Authentication Methods

* `GenerateCSRFToken() (string, error)` - Generate a CSRF token
* `IsTrustedSource(req *http.Request) bool` - Validate CSRF token
* `GetSession(c *gin.Context) (*Session, error)` - Retrieve session data

### Logging System

* `Info(message string, args ...interface{})` - Logs an informational message
* `Warn(message string, args ...interface{})` - Logs a warning message
* `Error(message string, args ...interface{})` - Logs an error message

## Migration Guide

### Upgrading to v2.0.0

Version 2.0.0 introduces several breaking changes to improve error handling, security, and maintainability. Follow this guide to update your application.

#### 1. Logger Interface Changes

The logging system has been completely refactored to support structured logging:

```go
// OLD (pre-v2.0.0)
s.Logger.Info("Connected to database", dbName)

// NEW (v2.0.0+)
s.Logger.Info("Connected to database", F("name", dbName))
```

All logger methods now accept a message string and a variable number of `LogField` objects. Use the `F()` helper function to create these fields.

#### 2. MongoDB Interface Changes

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

#### 3. Server Initialization Error Handling

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

#### 4. Memory Cache Configuration

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

### New Features Usage

#### Environment Variables Configuration

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

#### Rate Limiting

```go
// Add rate limiting to your server
import (
    "time"
    
    "github.com/tomskip123/EpicServer"
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

#### Security Headers

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

#### Structured Logging Configuration

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

## Contributing

### Getting Started

1. Fork the repository
2. Clone your fork:

```bash
git clone https://github.com/yourusername/EpicServer.git
```

3. Create your feature branch:

```bash
git checkout -b feature/amazing-feature
```

### Development

1. Ensure you have Go 1.16+ installed
2. Run tests before making changes:

```bash
go test -v ./...
```

### Testing Your Changes

The project includes tests for core functionality. Always run tests before submitting a PR:

```bash
# Run all tests
go test -v ./...

# Run specific tests (examples)
go test -run TestVerifyCSRFToken     # Test CSRF middleware
go test -run TestCompressMiddleware  # Test compression
go test -run TestServer_Start       # Test server startup
```

Key areas covered by tests:
* Server initialization and configuration
* Built-in middleware (CSRF, Compression, CORS, WWW redirect)
* Environment settings
* Server lifecycle
* Logger functionality

### Submitting Changes

1. Commit your changes:

```bash
git commit -m 'Add some amazing feature'
```

2. Push to your fork:

```bash
git push origin feature/amazing-feature
```

3. Open a Pull Request

### Code Style

* Follow standard Go formatting (`go fmt`)
* Add tests for new features
* Update documentation as needed
* Keep commits focused and atomic

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for details on changes in each version.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

Project Link: [https://github.com/tomskip123/EpicServer](https://github.com/tomskip123/EpicServer)
