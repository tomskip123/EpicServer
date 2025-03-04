---
title: "Basic API Example"
description: "A complete example of building a basic API with EpicServer."
summary: "Learn how to build a complete API with EpicServer, including routing, database integration, and authentication."
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 10
toc: true
seo:
  title: "Building a Basic API with EpicServer" # custom title (optional)
  description: "Step-by-step guide to building a complete API with EpicServer, including routing, database integration, and authentication." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Complete API Example

This example demonstrates how to build a complete API with EpicServer, including routing, database integration, and authentication.

### Project Structure

```
myapi/
├── main.go
├── go.mod
├── go.sum
├── handlers/
│   ├── users.go
│   └── auth.go
└── models/
    └── user.go
```

### Main Application

```go
// main.go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/tomskip123/EpicServer/v2"
    "github.com/tomskip123/EpicServer/db"
    
    "myapi/handlers"
)

func main() {
    // Initialize server with options
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetHost("localhost", 8080),
        EpicServer.SetSecretKey([]byte("your-secret-key")),
    })

    // Configure server with app layers
    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Add MongoDB connection
        EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
            ConnectionName: "default",
            URI:           "mongodb://localhost:27017",
            DatabaseName:  "myapi",
        }),
        
        // Configure routes
        EpicServer.WithRoutes(
            EpicServer.RouteGroup{
                Prefix: "/api/v1",
                Routes: []EpicServer.Route{
                    EpicServer.Get("/users", handlers.GetUsers),
                    EpicServer.Get("/users/:id", handlers.GetUser),
                    EpicServer.Post("/users", handlers.CreateUser),
                    EpicServer.Put("/users/:id", handlers.UpdateUser),
                    EpicServer.Delete("/users/:id", handlers.DeleteUser),
                },
            },
        ),
        
        // Add CORS support
        EpicServer.WithCors([]string{
            "http://localhost:3000",
            "https://myapp.example.com",
        }),
        
        // Add authentication
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
        
        // Configure public paths that don't require authentication
        EpicServer.WithPublicPaths(EpicServer.PublicPathConfig{
            Exact: []string{
                "/health",
                "/api/v1/users",
            },
            Prefix: []string{
                "/auth",
                "/public",
            },
        }),
    })

    // Start the server
    server.Start()
}
```

### User Model

```go
// models/user.go
package models

import (
    "time"
    
    "go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
    ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    Name      string             `bson:"name" json:"name"`
    Email     string             `bson:"email" json:"email"`
    CreatedAt time.Time          `bson:"created_at" json:"created_at"`
    UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}
```

### User Handlers

```go
// handlers/users.go
package handlers

import (
    "context"
    "net/http"
    "time"
    
    "github.com/gin-gonic/gin"
    "github.com/tomskip123/EpicServer/v2"
    "github.com/tomskip123/EpicServer/db"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/bson/primitive"
    
    "myapi/models"
)

// GetUsers returns all users
func GetUsers(c *gin.Context, s *EpicServer.Server) {
    // Get MongoDB client
    client, ok := EpicServerDb.GetMongoClient(s, "default")
    if !ok {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
        return
    }
    
    // Get users collection
    collection, err := EpicServerDb.GetMongoCollection(s, "default", "myapi", "users")
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to access collection"})
        return
    }
    
    // Find all users
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    cursor, err := collection.Find(ctx, bson.M{})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    defer cursor.Close(ctx)
    
    // Decode users
    var users []models.User
    if err := cursor.All(ctx, &users); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    
    c.JSON(http.StatusOK, users)
}

// GetUser returns a single user by ID
func GetUser(c *gin.Context, s *EpicServer.Server) {
    // Get user ID from URL parameter
    id := c.Param("id")
    
    // Convert string ID to ObjectID
    objectID, err := primitive.ObjectIDFromHex(id)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
        return
    }
    
    // Get MongoDB collection
    collection, err := EpicServerDb.GetMongoCollection(s, "default", "myapi", "users")
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to access collection"})
        return
    }
    
    // Find user by ID
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    var user models.User
    err = collection.FindOne(ctx, bson.M{"_id": objectID}).Decode(&user)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }
    
    c.JSON(http.StatusOK, user)
}

// CreateUser creates a new user
func CreateUser(c *gin.Context, s *EpicServer.Server) {
    // Parse request body
    var user models.User
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    // Set timestamps
    now := time.Now()
    user.CreatedAt = now
    user.UpdatedAt = now
    
    // Get MongoDB collection
    collection, err := EpicServerDb.GetMongoCollection(s, "default", "myapi", "users")
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to access collection"})
        return
    }
    
    // Insert user
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    result, err := collection.InsertOne(ctx, user)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    
    // Get inserted ID
    user.ID = result.InsertedID.(primitive.ObjectID)
    
    c.JSON(http.StatusCreated, user)
}

// UpdateUser updates an existing user
func UpdateUser(c *gin.Context, s *EpicServer.Server) {
    // Get user ID from URL parameter
    id := c.Param("id")
    
    // Convert string ID to ObjectID
    objectID, err := primitive.ObjectIDFromHex(id)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
        return
    }
    
    // Parse request body
    var user models.User
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    // Set update timestamp
    user.UpdatedAt = time.Now()
    
    // Get MongoDB collection
    collection, err := EpicServerDb.GetMongoCollection(s, "default", "myapi", "users")
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to access collection"})
        return
    }
    
    // Update user
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    update := bson.M{
        "$set": bson.M{
            "name":       user.Name,
            "email":      user.Email,
            "updated_at": user.UpdatedAt,
        },
    }
    
    result, err := collection.UpdateOne(ctx, bson.M{"_id": objectID}, update)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    
    if result.MatchedCount == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

// DeleteUser deletes a user
func DeleteUser(c *gin.Context, s *EpicServer.Server) {
    // Get user ID from URL parameter
    id := c.Param("id")
    
    // Convert string ID to ObjectID
    objectID, err := primitive.ObjectIDFromHex(id)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
        return
    }
    
    // Get MongoDB collection
    collection, err := EpicServerDb.GetMongoCollection(s, "default", "myapi", "users")
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to access collection"})
        return
    }
    
    // Delete user
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    result, err := collection.DeleteOne(ctx, bson.M{"_id": objectID})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    
    if result.DeletedCount == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}
```

### Authentication Hooks

```go
// handlers/auth.go
package handlers

import (
    "context"
    "time"
    
    "github.com/tomskip123/EpicServer/v2"
    "github.com/tomskip123/EpicServer/db"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/bson/primitive"
    
    "myapi/models"
)

// AuthHooks implements the EpicServer.AuthHooks interface
type AuthHooks struct {
    server *EpicServer.Server
}

// NewAuthHooks creates a new AuthHooks instance
func NewAuthHooks(server *EpicServer.Server) *AuthHooks {
    return &AuthHooks{
        server: server,
    }
}

// OnUserCreate is called when a new user is created during authentication
func (h *AuthHooks) OnUserCreate(claims EpicServer.Claims) (string, error) {
    // Get MongoDB collection
    collection, err := EpicServerDb.GetMongoCollection(h.server, "default", "myapi", "users")
    if err != nil {
        return "", err
    }
    
    // Create new user
    user := models.User{
        Name:      claims.Name,
        Email:     claims.Email,
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
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
    collection, err := EpicServerDb.GetMongoCollection(h.server, "default", "myapi", "users")
    if err != nil {
        return nil, err
    }
    
    // Try to find existing user
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    var user models.User
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
```

### Registering Auth Hooks

Add this to your main.go:

```go
// Register auth hooks
authHooks := handlers.NewAuthHooks(server)
server.UpdateAppLayer([]EpicServer.AppLayer{
    EpicServer.WithAuthHooks(authHooks),
})
```

## Running the API

To run the API:

```bash
go mod init myapi
go mod tidy
go run main.go
```

The API will be available at http://localhost:8080/api/v1/users.