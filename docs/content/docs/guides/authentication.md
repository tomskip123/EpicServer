---
title: "Authentication"
description: "Learn how to implement authentication in EpicServer."
summary: "A comprehensive guide to setting up authentication in EpicServer."
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 40
toc: true
seo:
  title: "EpicServer Authentication Guide" # custom title (optional)
  description: "Learn how to implement authentication, session management, and security in EpicServer." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Authentication in EpicServer

EpicServer provides a flexible authentication system supporting multiple providers and custom authentication hooks.

### Setting Up Authentication

```go
package main

import (
    "github.com/tomskip123/EpicServer/v2"
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

### Configuring Public Paths

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

### Custom Authentication Hooks

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

### Available Auth Providers

* Google (`"google"`)
* Basic Auth (`"basic"`)
* Custom providers can be added by implementing the provider interface

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

### Authentication Endpoints

The following endpoints are automatically created:

* `/auth/:provider` - Initiates authentication flow
* `/auth/:provider/callback` - OAuth callback URL
* `/auth/logout` - Handles user logout

### Session Management

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

## Security Features

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

### Rate Limiting

EpicServer includes a built-in rate limiter to prevent abuse:

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

### Complete Authentication Example

Here's a complete example with MongoDB integration:

```go
package main

import (
    "context"
    "time"
    
    "github.com/gin-gonic/gin"
    "github.com/tomskip123/EpicServer/v2"
    "github.com/tomskip123/EpicServer/db"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/bson/primitive"
)

// User model
type User struct {
    ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    Email     string             `bson:"email" json:"email"`
    Name      string             `bson:"name" json:"name"`
    CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// AuthHooks implements the EpicServer.AuthHooks interface
type AuthHooks struct {
    server *EpicServer.Server
}

// OnUserCreate is called when a new user is created during authentication
func (h *AuthHooks) OnUserCreate(claims EpicServer.Claims) (string, error) {
    // Get MongoDB collection
    collection, err := EpicServerDb.GetMongoCollection(h.server, "default", "myapp", "users")
    if err != nil {
        return "", err
    }
    
    // Create new user
    user := User{
        Email:     claims.Email,
        Name:      claims.Name,
        CreatedAt: time.Now(),
    }
    
    // Insert user
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    result, err := collection.InsertOne(ctx, user)
    if err != nil {
        return "", err
    }
    
    // Return user ID
    return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

// GetUserOrCreate is called during authentication to get or create a user
func (h *AuthHooks) GetUserOrCreate(claims EpicServer.Claims) (*EpicServer.CookieContents, error) {
    // Get MongoDB collection
    collection, err := EpicServerDb.GetMongoCollection(h.server, "default", "myapp", "users")
    if err != nil {
        return nil, err
    }
    
    // Try to find existing user
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    var user User
    err = collection.FindOne(ctx, bson.M{"email": claims.Email}).Decode(&user)
    
    // If user doesn't exist, create a new one
    if err != nil {
        userID, err := h.OnUserCreate(claims)
        if err != nil {
            return nil, err
        }
        
        // Return session data
        return &EpicServer.CookieContents{
            UserId:     userID,
            Email:      claims.Email,
            SessionId:  primitive.NewObjectID().Hex(),
            IsLoggedIn: true,
            ExpiresOn:  time.Now().Add(time.Hour * 24),
        }, nil
    }
    
    // Return session data for existing user
    return &EpicServer.CookieContents{
        UserId:     user.ID.Hex(),
        Email:      user.Email,
        SessionId:  primitive.NewObjectID().Hex(),
        IsLoggedIn: true,
        ExpiresOn:  time.Now().Add(time.Hour * 24),
    }, nil
}

func main() {
    // Initialize server
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetHost("localhost", 8080),
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })
    
    // Create auth hooks
    authHooks := &AuthHooks{server: server}
    
    // Configure server
    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Add MongoDB connection
        EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
            ConnectionName: "default",
            URI:           "mongodb://localhost:27017",
            DatabaseName:  "myapp",
        }),
        
        // Configure authentication
        EpicServer.WithAuth([]EpicServer.Provider{
            {
                Name:         "google",
                ClientId:     "your-client-id",
                ClientSecret: "your-client-secret",
                Callback:     "http://localhost:8080/auth/google/callback",
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
        
        // Add auth hooks
        EpicServer.WithAuthHooks(authHooks),
        
        // Configure public paths
        EpicServer.WithPublicPaths(EpicServer.PublicPathConfig{
            Exact: []string{
                "/health",
            },
            Prefix: []string{
                "/auth",
                "/public",
            },
        }),
        
        // Add CSRF protection
        EpicServer.WithCSRFProtection(),
        
        // Add routes
        EpicServer.WithRoutes(
            EpicServer.RouteGroup{
                Prefix: "/api/v1",
                Routes: []EpicServer.Route{
                    EpicServer.Get("/profile", HandleProfile),
                },
            },
        ),
    })
    
    // Start the server
    server.Start()
}

// HandleProfile returns the user's profile
func HandleProfile(c *gin.Context, s *EpicServer.Server) {
    // Get session
    session, err := EpicServer.GetSession(c)
    if err != nil {
        c.JSON(401, gin.H{"error": "Unauthorized"})
        return
    }
    
    // Get user from database
    collection, err := EpicServerDb.GetMongoCollection(s, "default", "myapp", "users")
    if err != nil {
        c.JSON(500, gin.H{"error": "Database error"})
        return
    }
    
    // Convert user ID to ObjectID
    userID, err := primitive.ObjectIDFromHex(session.UserId)
    if err != nil {
        c.JSON(400, gin.H{"error": "Invalid user ID"})
        return
    }
    
    // Find user
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    var user User
    err = collection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
    if err != nil {
        c.JSON(404, gin.H{"error": "User not found"})
        return
    }
    
    // Return user profile
    c.JSON(200, user)
}
``` 