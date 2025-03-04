---
title: "Configuration"
description: "Learn how to configure EpicServer."
summary: "A comprehensive guide to configuring EpicServer using different methods."
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 70
toc: true
seo:
  title: "EpicServer Configuration Guide" # custom title (optional)
  description: "Learn how to configure EpicServer using environment variables, configuration files, and code." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Configuration in EpicServer

EpicServer provides a flexible configuration system that allows you to customize your server through code, environment variables, and configuration files. This guide will show you how to use these different configuration methods effectively.

### Basic Configuration

The simplest way to configure EpicServer is through the server initialization parameters:

```go
package main

import (
    "github.com/tomskip123/EpicServer/v2"
)

func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // Configure host and port
            EpicServer.WithHost("localhost", 8080),
            
            // Configure secret key
            EpicServer.WithSecretKey([]byte("your-secret-key")),
        },
    })
    
    server.Start()
}
```

### Server Options

EpicServer provides several options for configuring your server:

```go
server := EpicServer.NewServer(&EpicServer.NewServerParam{
    AppLayer: []EpicServer.AppLayer{
        // Host and port
        EpicServer.WithHost("localhost", 8080),
        
        // Secret key for encryption
        EpicServer.WithSecretKey([]byte("your-secret-key")),
        
        // Trusted proxies
        EpicServer.WithTrustedProxies([]string{"192.168.1.1", "10.0.0.1"}),
        
        // CORS configuration
        EpicServer.WithCORS(&EpicServer.CORSConfig{
            AllowOrigins:     []string{"https://example.com"},
            AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
            AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
            ExposeHeaders:    []string{"Content-Length"},
            AllowCredentials: true,
            MaxAge:           12 * time.Hour,
        }),
        
        // Static file serving
        EpicServer.WithStaticFiles("/static", "./static"),
        
        // Public paths (no authentication required)
        EpicServer.WithPublicPaths(EpicServer.PublicPathConfig{
            Exact: []string{"/health", "/login"},
            Prefix: []string{"/public", "/api/v1/public"},
        }),
    },
})
```

### Environment Variables

EpicServer can be configured using environment variables:

```env
# Server configuration
HOST=localhost
PORT=8080
SECRET_KEY=your-secret-key
TRUSTED_PROXIES=192.168.1.1,10.0.0.1

# Database configuration
MONGO_URI=mongodb://localhost:27017
MONGO_DB=myapp
POSTGRES_URI=postgres://user:password@localhost:5432/myapp
MYSQL_URI=mysql://user:password@localhost:3306/myapp

# Authentication configuration
SECURE_COOKIE_HASH_KEY=base64_encoded_32_byte_key
SECURE_COOKIE_BLOCK_KEY=base64_encoded_32_byte_key
ENCRYPTION_KEY=32_byte_hex_encoded_key

# Logging configuration
LOG_LEVEL=debug
LOG_FORMAT=json

# Cache configuration
REDIS_URI=redis://localhost:6379
MEMORY_CACHE_EXPIRATION=5m
MEMORY_CACHE_CLEANUP_INTERVAL=10m
```

### Loading Environment Variables

EpicServer automatically loads environment variables when you create a new server instance. You can also explicitly load them:

```go
// Load environment variables from .env file
EpicServer.LoadEnv()

// Create server (will use environment variables)
server := EpicServer.NewServer(&EpicServer.NewServerParam{})
```

### Configuration Files

You can also use configuration files to configure EpicServer. Create a `config.json` file:

```json
{
  "host": "localhost",
  "port": 8080,
  "secretKey": "your-secret-key",
  "trustedProxies": ["192.168.1.1", "10.0.0.1"],
  "cors": {
    "allowOrigins": ["https://example.com"],
    "allowMethods": ["GET", "POST", "PUT", "DELETE"],
    "allowHeaders": ["Origin", "Content-Type", "Authorization"],
    "exposeHeaders": ["Content-Length"],
    "allowCredentials": true,
    "maxAge": 43200
  },
  "database": {
    "mongo": {
      "uri": "mongodb://localhost:27017",
      "database": "myapp"
    },
    "postgres": {
      "uri": "postgres://user:password@localhost:5432/myapp"
    }
  },
  "auth": {
    "providers": [
      {
        "name": "google",
        "clientId": "your-client-id",
        "clientSecret": "your-client-secret",
        "callback": "http://localhost:8080/auth/google/callback"
      }
    ],
    "session": {
      "cookieName": "auth_session",
      "cookieDomain": "localhost",
      "cookieSecure": false,
      "cookieHTTPOnly": true,
      "sessionDuration": 86400
    }
  },
  "logging": {
    "level": "debug",
    "format": "json"
  },
  "cache": {
    "redis": {
      "address": "localhost:6379",
      "password": "",
      "db": 0
    },
    "memory": {
      "defaultExpiration": 300,
      "cleanupInterval": 600
    }
  }
}
```

Then load the configuration file:

```go
// Load configuration from file
config, err := EpicServer.LoadConfig("config.json")
if err != nil {
    panic(err)
}

// Create server with loaded configuration
server := EpicServer.NewServer(&EpicServer.NewServerParam{
    Config: config,
})
```

### Configuration Priority

EpicServer uses the following priority order when resolving configuration:

1. Explicit configuration in code
2. Configuration files
3. Environment variables
4. Default values

This means that values specified in code will override values from configuration files, which will override environment variables.

### Dynamic Configuration

You can update the server configuration after initialization:

```go
// Create server
server := EpicServer.NewServer(&EpicServer.NewServerParam{})

// Update configuration
server.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithHost("0.0.0.0", 3000),
    EpicServer.WithCORS(&EpicServer.CORSConfig{
        AllowOrigins: []string{"https://example.com"},
    }),
})
```

### Configuration Validation

EpicServer validates your configuration when you create a new server instance. If there are any issues with your configuration, the server will return an error:

```go
server, err := EpicServer.NewServer(&EpicServer.NewServerParam{
    // Configuration...
})

if err != nil {
    // Handle configuration error
    panic(err)
}
```

## Common Configuration Scenarios

### Configuring for Development

```go
server := EpicServer.NewServer(&EpicServer.NewServerParam{
    AppLayer: []EpicServer.AppLayer{
        // Development host and port
        EpicServer.WithHost("localhost", 8080),
        
        // Development database
        EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
            ConnectionName: "default",
            URI:           "mongodb://localhost:27017",
            DatabaseName:  "myapp_dev",
        }),
        
        // Development logging
        EpicServer.WithLogConfig(EpicServer.LogConfig{
            Level:  "debug",
            Format: "text",
        }),
        
        // In-memory cache for development
        EpicServer.WithMemoryCache(&EpicServer.MemoryCacheConfig{
            DefaultExpiration: 5 * time.Minute,
            CleanupInterval:   10 * time.Minute,
            ConnectionName:    "default",
        }),
        
        // CORS for development
        EpicServer.WithCORS(&EpicServer.CORSConfig{
            AllowOrigins:     []string{"http://localhost:3000"},
            AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
            AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
            AllowCredentials: true,
        }),
    },
})
```

### Configuring for Production

```go
server := EpicServer.NewServer(&EpicServer.NewServerParam{
    AppLayer: []EpicServer.AppLayer{
        // Production host and port
        EpicServer.WithHost("0.0.0.0", 8080),
        
        // Production database
        EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
            ConnectionName: "default",
            URI:           os.Getenv("MONGO_URI"),
            DatabaseName:  "myapp_prod",
        }),
        
        // Production logging
        EpicServer.WithLogConfig(EpicServer.LogConfig{
            Level:  "info",
            Format: "json",
        }),
        
        // Redis cache for production
        EpicServer.WithRedisCache(&EpicServer.RedisCacheConfig{
            ConnectionName: "default",
            Address:        os.Getenv("REDIS_URI"),
            Password:       os.Getenv("REDIS_PASSWORD"),
            DB:             0,
        }),
        
        // CORS for production
        EpicServer.WithCORS(&EpicServer.CORSConfig{
            AllowOrigins:     []string{"https://example.com"},
            AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
            AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
            AllowCredentials: true,
            MaxAge:           12 * time.Hour,
        }),
        
        // Rate limiting for production
        EpicServer.WithRateLimiter(EpicServer.RateLimiterConfig{
            MaxRequests:   100,
            Interval:      time.Minute,
            BlockDuration: 5 * time.Minute,
        }),
    },
})
```

### Environment-Based Configuration

```go
package main

import (
    "os"
    "time"
    
    "github.com/tomskip123/EpicServer/v2"
    "github.com/tomskip123/EpicServer/db"
)

func main() {
    // Load environment variables
    EpicServer.LoadEnv()
    
    // Determine environment
    env := os.Getenv("APP_ENV")
    if env == "" {
        env = "development"
    }
    
    // Create base configuration
    appLayers := []EpicServer.AppLayer{
        // Common configuration
        EpicServer.WithHost(os.Getenv("HOST"), 8080),
        EpicServer.WithSecretKey([]byte(os.Getenv("SECRET_KEY"))),
    }
    
    // Add environment-specific configuration
    switch env {
    case "production":
        // Production configuration
        appLayers = append(appLayers,
            EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
                ConnectionName: "default",
                URI:           os.Getenv("MONGO_URI"),
                DatabaseName:  "myapp_prod",
            }),
            EpicServer.WithLogConfig(EpicServer.LogConfig{
                Level:  "info",
                Format: "json",
            }),
            EpicServer.WithRedisCache(&EpicServer.RedisCacheConfig{
                ConnectionName: "default",
                Address:        os.Getenv("REDIS_URI"),
                Password:       os.Getenv("REDIS_PASSWORD"),
                DB:             0,
            }),
            EpicServer.WithRateLimiter(EpicServer.RateLimiterConfig{
                MaxRequests:   100,
                Interval:      time.Minute,
                BlockDuration: 5 * time.Minute,
            }),
        )
    case "staging":
        // Staging configuration
        appLayers = append(appLayers,
            EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
                ConnectionName: "default",
                URI:           os.Getenv("MONGO_URI"),
                DatabaseName:  "myapp_staging",
            }),
            EpicServer.WithLogConfig(EpicServer.LogConfig{
                Level:  "debug",
                Format: "json",
            }),
            EpicServer.WithRedisCache(&EpicServer.RedisCacheConfig{
                ConnectionName: "default",
                Address:        os.Getenv("REDIS_URI"),
                Password:       os.Getenv("REDIS_PASSWORD"),
                DB:             1,
            }),
        )
    default:
        // Development configuration
        appLayers = append(appLayers,
            EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
                ConnectionName: "default",
                URI:           "mongodb://localhost:27017",
                DatabaseName:  "myapp_dev",
            }),
            EpicServer.WithLogConfig(EpicServer.LogConfig{
                Level:  "debug",
                Format: "text",
            }),
            EpicServer.WithMemoryCache(&EpicServer.MemoryCacheConfig{
                DefaultExpiration: 5 * time.Minute,
                CleanupInterval:   10 * time.Minute,
                ConnectionName:    "default",
            }),
        )
    }
    
    // Create server with environment-specific configuration
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: appLayers,
    })
    
    // Start server
    server.Start()
}
```

## Complete Configuration Example

Here's a complete example demonstrating various configuration options:

```go
package main

import (
    "os"
    "time"
    
    "github.com/tomskip123/EpicServer/v2"
    "github.com/tomskip123/EpicServer/db"
)

func main() {
    // Load environment variables
    EpicServer.LoadEnv()
    
    // Create server
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // Server configuration
            EpicServer.WithHost(os.Getenv("HOST"), 8080),
            EpicServer.WithSecretKey([]byte(os.Getenv("SECRET_KEY"))),
            EpicServer.WithTrustedProxies([]string{"192.168.1.1", "10.0.0.1"}),
            
            // Database configuration
            EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
                ConnectionName: "default",
                URI:           os.Getenv("MONGO_URI"),
                DatabaseName:  os.Getenv("MONGO_DB"),
            }),
            EpicServerDb.WithPostgres(&EpicServerDb.PostgresConfig{
                ConnectionName: "postgres",
                URI:           os.Getenv("POSTGRES_URI"),
            }),
            
            // Cache configuration
            EpicServer.WithRedisCache(&EpicServer.RedisCacheConfig{
                ConnectionName: "default",
                Address:        os.Getenv("REDIS_URI"),
                Password:       os.Getenv("REDIS_PASSWORD"),
                DB:             0,
            }),
            EpicServer.WithMemoryCache(&EpicServer.MemoryCacheConfig{
                ConnectionName:    "local",
                DefaultExpiration: 5 * time.Minute,
                CleanupInterval:   10 * time.Minute,
            }),
            
            // Authentication configuration
            EpicServer.WithAuth([]EpicServer.Provider{
                {
                    Name:         "google",
                    ClientId:     os.Getenv("GOOGLE_CLIENT_ID"),
                    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
                    Callback:     os.Getenv("GOOGLE_CALLBACK_URL"),
                },
            }, &EpicServer.SessionConfig{
                CookieName:      "auth_session",
                CookieDomain:    os.Getenv("COOKIE_DOMAIN"),
                CookieSecure:    os.Getenv("APP_ENV") == "production",
                CookieHTTPOnly:  true,
                SessionDuration: 24 * time.Hour,
            }),
            EpicServer.WithAuthMiddleware(EpicServer.SessionConfig{
                CookieName:   "auth_session",
                CookieDomain: os.Getenv("COOKIE_DOMAIN"),
                CookieSecure: os.Getenv("APP_ENV") == "production",
            }),
            
            // Public paths
            EpicServer.WithPublicPaths(EpicServer.PublicPathConfig{
                Exact: []string{
                    "/health",
                    "/login",
                },
                Prefix: []string{
                    "/auth",
                    "/public",
                    "/api/v1/public",
                },
            }),
            
            // CORS configuration
            EpicServer.WithCORS(&EpicServer.CORSConfig{
                AllowOrigins:     []string{os.Getenv("CORS_ALLOW_ORIGIN")},
                AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
                AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
                ExposeHeaders:    []string{"Content-Length"},
                AllowCredentials: true,
                MaxAge:           12 * time.Hour,
            }),
            
            // Logging configuration
            EpicServer.WithLogConfig(EpicServer.LogConfig{
                Level:           os.Getenv("LOG_LEVEL"),
                Format:          os.Getenv("LOG_FORMAT"),
                LogRequests:     true,
                LogRequestBody:  false,
                LogResponseBody: false,
            }),
            
            // Static files
            EpicServer.WithStaticFiles("/static", "./static"),
            
            // Security features
            EpicServer.WithCSRFProtection(),
            EpicServer.WithRateLimiter(EpicServer.RateLimiterConfig{
                MaxRequests:    100,
                Interval:       time.Minute,
                BlockDuration:  5 * time.Minute,
                ExcludedPaths:  []string{"/health", "/static/*"},
            }),
            
            // Routes
            EpicServer.WithRoutes(
                EpicServer.RouteGroup{
                    Prefix: "/api/v1",
                    Routes: []EpicServer.Route{
                        EpicServer.Get("/users", GetUsers),
                        EpicServer.Get("/users/:id", GetUser),
                        EpicServer.Post("/users", CreateUser),
                        EpicServer.Put("/users/:id", UpdateUser),
                        EpicServer.Delete("/users/:id", DeleteUser),
                    },
                },
            ),
        },
    })
    
    // Start server
    server.Start()
}

// Handler functions
func GetUsers(c *gin.Context, s *EpicServer.Server) {
    // Implementation...
}

func GetUser(c *gin.Context, s *EpicServer.Server) {
    // Implementation...
}

func CreateUser(c *gin.Context, s *EpicServer.Server) {
    // Implementation...
}

func UpdateUser(c *gin.Context, s *EpicServer.Server) {
    // Implementation...
}

func DeleteUser(c *gin.Context, s *EpicServer.Server) {
    // Implementation...
}
``` 