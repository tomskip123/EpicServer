---
title: "Routing"
description: "Learn how to define routes in EpicServer."
summary: "A comprehensive guide to setting up routes and handling requests in EpicServer."
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 10
toc: true
seo:
  title: "EpicServer Routing Guide" # custom title (optional)
  description: "Learn how to define routes, handle requests, and organize your API endpoints in EpicServer." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Routing in EpicServer

EpicServer provides a flexible routing system that allows you to organize your routes into groups and access server instance in your handlers.

### Basic Route Setup

```go
package main

import (
    "github.com/tomskip123/EpicServer/v2"
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

### Route Handlers

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

### Available Route Methods

* `Get(path string, handler HandlerFunc)` - HTTP GET
* `Post(path string, handler HandlerFunc)` - HTTP POST
* `Put(path string, handler HandlerFunc)` - HTTP PUT
* `Patch(path string, handler HandlerFunc)` - HTTP PATCH
* `Delete(path string, handler HandlerFunc)` - HTTP DELETE

### Route Groups

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

### Accessing Server Components

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

### URL Parameters

Access URL parameters using the Gin context:

```go
func HandleUser(c *gin.Context, s *EpicServer.Server) {
    // Get URL parameter
    userId := c.Param("id")
    
    // Use the parameter
    c.JSON(200, gin.H{"userId": userId})
}
```

### Query Parameters

Access query parameters using the Gin context:

```go
func HandleUsers(c *gin.Context, s *EpicServer.Server) {
    // Get query parameters
    limit := c.DefaultQuery("limit", "10")
    offset := c.DefaultQuery("offset", "0")
    
    // Use the parameters
    c.JSON(200, gin.H{"limit": limit, "offset": offset})
}
```

### Request Body

Parse request body using the Gin context:

```go
func HandleCreateUser(c *gin.Context, s *EpicServer.Server) {
    // Define a struct for the request body
    var user struct {
        Name  string `json:"name"`
        Email string `json:"email"`
    }
    
    // Parse the request body
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    
    // Use the parsed data
    c.JSON(200, gin.H{"name": user.Name, "email": user.Email})
}
``` 