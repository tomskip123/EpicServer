# EpicServer

> A powerful, flexible, and production-ready Go web server built on top of Gin framework.

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

4. [Security](#security)
   - [Authentication Setup](#authentication-setup)
   - [CSRF Protection](#csrf-protection)
   - [Security Headers](#security-headers)
   - [Environment Variables](#environment-variables)

5. [API Reference](#api-reference)
   - [Server Options](#server-options)
   - [Database Methods](#database-methods)
   - [Cache Methods](#cache-methods)
   - [Authentication Methods](#authentication-methods)

6. [Testing](#testing)
   - [Unit Testing](#unit-testing)
   - [Mocking Database](#mocking-database)
   - [Authentication Testing](#authentication-testing)
   - [Middleware Testing](#middleware-testing)
   - [Integration Testing](#integration-testing)
   - [Test Utilities](#test-utilities)
   - [Best Practices](#best-practices)

7. [Contributing](#contributing)
8. [License](#license)
9. [Support](#support)

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
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            EpicServer.WithHealthCheck("/health"),
            EpicServer.WithEnvironment("development"),
        },
    })

    server.Start()
}
```

### Basic Example

Here's a complete example with routing, database, and authentication:

```go
package main

import (
    "github.com/tomskip123/EpicServer"
    "github.com/tomskip123/EpicServer/db"
)

func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        Configs: []EpicServer.Option{
            EpicServer.SetHost("localhost", 8080),
            EpicServer.SetSecretKey([]byte("your-secret-key")),
        },
        AppLayer: []EpicServer.AppLayer{
            // Basic setup
            EpicServer.WithEnvironment("development"),
            EpicServer.WithCompression(),
            
            // Database
            EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
                ConnectionName: "default",
                URI: "mongodb://localhost:27017",
                DatabaseName: "myapp",
            }),
            
            // Routes
            EpicServer.WithRoutes(
                EpicServer.RouteGroup{
                    Prefix: "/api",
                    Routes: []EpicServer.Route{
                        EpicServer.Get("/users", HandleUsers),
                    },
                },
            ),
        },
    })

    server.Start()
}

func HandleUsers(c *gin.Context, s *EpicServer.Server) {
    db := EpicServerDb.GetMongoClient(s, "default")
    // Handle request...
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
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        Configs: []EpicServer.Option{
            EpicServer.SetHost("localhost", 8080),
            EpicServer.SetSecretKey([]byte("your-secret-key")),
        },
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

- `Get(path string, handler HandlerFunc)` - HTTP GET
- `Post(path string, handler HandlerFunc)` - HTTP POST
- `Put(path string, handler HandlerFunc)` - HTTP PUT
- `Patch(path string, handler HandlerFunc)` - HTTP PATCH
- `Delete(path string, handler HandlerFunc)` - HTTP DELETE

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

- Google (`"google"`)
- Basic Auth (`"basic"`)
- Custom providers can be added by implementing the provider interface

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

- `/auth/:provider` - Initiates authentication flow
- `/auth/:provider/callback` - OAuth callback URL
- `/auth/logout` - Handles user logout

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
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // Configure MongoDB
            EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
                ConnectionName: "default",
                URI:           "mongodb://localhost:27017",
                DatabaseName:  "myapp",
            }),
        },
    })

    // Use MongoDB in your handlers
    func MyHandler(c *gin.Context) {
        // Get MongoDB client
        client := EpicServerDb.GetMongoClient(server, "default")
        
        // Get specific collection
        collection := EpicServerDb.GetMongoCollection(server, "default", "myapp", "users")
        
        // Use MongoDB helper functions
        objectID := EpicServerDb.StringToObjectID("507f1f77bcf86cd799439011")
        ids := EpicServerDb.StringArrayToObjectIDArray([]string{"507f1f77bcf86cd799439011"})
        
        // Create indexes
        indexes := []mongo.IndexModel{
            {
                Keys: bson.D{{Key: "email", Value: 1}},
                Options: options.Index().SetUnique(true),
            },
        }
        EpicServerDb.UpdateIndexes(context.Background(), collection, indexes)
    }
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
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
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
        },
    })

    // Use PostgreSQL in your handlers
    func MyHandler(c *gin.Context) {
        db := EpicServerDb.GetPostgresDB(server, "default")
        rows, err := db.Query("SELECT * FROM users")
    }
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
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // Configure MySQL
            EpicServerDb.WithMySQL(EpicServerDb.MySQLConfig{
                ConnectionName: "default",
                Host:          "localhost",
                Port:          3306,
                User:          "root",
                Password:      "password",
                Database:      "myapp",
            }),
        },
    })

    // Use MySQL in your handlers
    func MyHandler(c *gin.Context) {
        db := EpicServerDb.GetMySQLDB(server, "default")
        rows, err := db.Query("SELECT * FROM users")
    }
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

The memory cache provides simple key-value storage with expiration:

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

- In-memory key-value storage
- Automatic expiration of cached items
- Thread-safe operations
- Zero configuration required
- Multiple named cache instances

#### Cache Methods

- `Set(key string, value interface{}, duration time.Duration)` - Store a value with expiration
- `Get(key string) (interface{}, bool)` - Retrieve a value if it exists
- `Delete(key string)` - Remove a value from the cache

### Static File Serving

EpicServer provides flexible options for serving static files and Single Page Applications (SPAs).

#### Serving Static Directories

Serve an entire directory of static files:

```go
//go:embed assets/*
var assets embed.FS

func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // Serve static files from the embedded assets directory
            EpicServer.WithStaticDirectory(
                "/static",         // URL path
                &assets,          // Embedded filesystem
                "assets",         // Directory in embedded filesystem
            ),
        },
    })
}
```

#### Serving Individual Static Files

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

- Embedded file system support using Go 1.16+ `embed` package
- Automatic MIME type detection
- Custom MIME type configuration
- SPA route fallback support
- Directory listing prevention
- Efficient file serving

#### Static File Configuration

The static file system supports:

- Multiple static directories
- Mixed static files and API routes
- Custom 404 handling
- Secure file serving
- File type restrictions
- Path normalization

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
- Automatic gzip compression
- Smart cache control headers
- Asset-specific caching rules
- Conditional compression based on Accept-Encoding

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
- Origin validation
- Configurable allowed origins
- Preflight request handling
- Custom headers support
- Credential support

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
- Automatic token generation
- Token validation
- Trusted source bypass
- Custom token storage
- Header/Form support

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
- Automatic www detection
- Permanent redirects (301)
- HTTPS upgrade support
- Path preservation

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
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security: max-age=31536000; includeSubDomains
- Content-Security-Policy: configurable

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
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security: max-age=31536000; includeSubDomains
- Content-Security-Policy: configurable

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
- `StringToObjectID(id string)` - Convert string to MongoDB ObjectID
- `StringArrayToObjectIDArray(ids []string)` - Convert string array to ObjectID array
- `UpdateIndexes(ctx, collection, indexes)` - Create or update collection indexes
- `StringArrayContains(array []string, value string)` - Check if string array contains value

### Cache Methods

- `Set(key string, value interface{}, duration time.Duration)` - Store a value with expiration
- `Get(key string) (interface{}, bool)` - Retrieve a value if it exists
- `Delete(key string)` - Remove a value from the cache

### Authentication Methods

- `GenerateCSRFToken() (string, error)` - Generate a CSRF token
- `IsTrustedSource(req *http.Request) bool` - Validate CSRF token
- `GetSession(c *gin.Context) (*Session, error)` - Retrieve session data

## Testing

EpicServer provides testing utilities and helpers for unit testing, integration testing, and mocking server components.

### Unit Testing

Test your handlers and middleware using the test utilities:

```go
package handlers_test

import (
    "testing"
    "net/http"
    "net/http/httptest"
    "github.com/tomskip123/EpicServer"
    "github.com/tomskip123/EpicServer/test"
)

func TestUserHandler(t *testing.T) {
    // Create test server
    server := test.NewTestServer([]EpicServer.AppLayer{
        // Add test configurations
        EpicServer.WithEnvironment("test"),
    })
    
    // Create test request
    w := httptest.NewRecorder()
    req := httptest.NewRequest("GET", "/users", nil)
    
    // Execute request
    server.Engine.ServeHTTP(w, req)
    
    // Assert response
    if w.Code != http.StatusOK {
        t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
    }
}
```

### Mocking Database

Mock database connections for testing:

```go
package db_test

import (
    "testing"
    "github.com/tomskip123/EpicServer"
    "github.com/tomskip123/EpicServer/db"
    "github.com/tomskip123/EpicServer/test"
)

func TestWithMockMongo(t *testing.T) {
    // Create mock database
    mockDB := test.NewMockDB()
    
    server := test.NewTestServer([]EpicServer.AppLayer{
        // Add mock database
        test.WithMockMongo(mockDB, "default"),
    })
    
    // Use mock database in tests
    db := EpicServerDb.GetMongoClient(server, "default")
    
    // Assert mock calls
    mockDB.AssertCalled(t, "Insert", "users")
}
```

### Authentication Testing

Test authentication flows:

```go
package auth_test

import (
    "testing"
    "github.com/tomskip123/EpicServer"
    "github.com/tomskip123/EpicServer/test"
)

func TestAuthFlow(t *testing.T) {
    // Create mock auth provider
    mockAuth := test.NewMockAuthProvider()
    
    server := test.NewTestServer([]EpicServer.AppLayer{
        // Configure mock auth
        EpicServer.WithAuth([]EpicServer.Provider{
            {
                Name: "mock",
                ClientId: "test-id",
                ClientSecret: "test-secret",
                Callback: "http://localhost/auth/mock/callback",
            },
        }, &EpicServer.SessionConfig{
            CookieName: "test_session",
        }),
    })
    
    // Test auth endpoints
    test.SimulateLogin(t, server, "mock")
    
    // Assert session created
    if !mockAuth.SessionExists("test-user") {
        t.Error("Expected session to exist")
    }
}
```

### Middleware Testing

Test custom middleware:

```go
package middleware_test

import (
    "testing"
    "net/http"
    "github.com/tomskip123/EpicServer"
    "github.com/tomskip123/EpicServer/test"
)

func TestCustomMiddleware(t *testing.T) {
    server := test.NewTestServer([]EpicServer.AppLayer{
        // Add test middleware
        func(s *EpicServer.Server) {
            s.Engine.Use(func(c *gin.Context) {
                c.Set("test-key", "test-value")
                c.Next()
            })
        },
    })
    
    // Test middleware
    test.ExecuteMiddleware(t, server, func(c *gin.Context) {
        value, exists := c.Get("test-key")
        if !exists || value != "test-value" {
            t.Error("Middleware did not set expected value")
        }
    })
}
```

### Integration Testing

Test complete API flows:

```go
package integration_test

import (
    "testing"
    "github.com/tomskip123/EpicServer"
    "github.com/tomskip123/EpicServer/test"
)

func TestAPIFlow(t *testing.T) {
    // Setup test environment
    env := test.NewTestEnvironment()
    defer env.Cleanup()
    
    // Create server with test configuration
    server := env.NewServer([]EpicServer.AppLayer{
        EpicServer.WithEnvironment("test"),
        // Add other test configurations
    })
    
    // Execute test scenarios
    t.Run("Create User", func(t *testing.T) {
        // Test user creation
        test.CreateUser(t, server, testUser)
    })
    
    t.Run("Authentication", func(t *testing.T) {
        // Test login flow
        test.Login(t, server, testUser)
    })
    
    t.Run("API Access", func(t *testing.T) {
        // Test protected endpoints
        test.AccessProtectedEndpoint(t, server, testUser)
    })
}
```

### Test Utilities

The test package provides several helpers:

- `test.NewTestServer()` - Create a server instance for testing
- `test.NewMockDB()` - Create mock database implementations
- `test.NewTestEnvironment()` - Setup complete test environment
- `test.SimulateLogin()` - Simulate authentication flow
- `test.ExecuteMiddleware()` - Test middleware in isolation

### Best Practices

1. Use test environment variables
```go
func init() {
    os.Setenv("GO_ENV", "test")
    os.Setenv("SECRET_KEY", "test-secret-key")
}
```

2. Clean up test resources
```go
defer func() {
    // Clean up test database
    test.CleanupTestDB()
    // Remove test files
    test.CleanupTestFiles()
}()
```

3. Use test configurations
```go
testConfig := &EpicServer.Config{
    Server: struct {
        Host: "localhost",
        Port: 0, // Random port for testing
    },
}
```

4. Isolate test databases
```go
mongoConfig := &EpicServerDb.MongoConfig{
    URI: "mongodb://localhost:27017",
    DatabaseName: "test_db_" + randomString(),
}
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

Project Link: [https://github.com/tomskip123/EpicServer](https://github.com/tomskip123/EpicServer)
