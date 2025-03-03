---
title: "Routing"
description: "Learn how to define and manage routes in EpicServer."
summary: "Complete guide to defining and managing HTTP routes in EpicServer."
date: 2023-09-07T16:06:50+02:00
lastmod: 2023-09-07T16:06:50+02:00
draft: false
weight: 10
toc: true
seo:
  title: "EpicServer Routing Guide" # custom title (optional)
  description: "Learn how to define, manage, and organize HTTP routes in EpicServer." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Introduction to Routing

Routing is a fundamental concept in web server development. In EpicServer, routing refers to how HTTP requests are directed to the appropriate handler functions based on the request URL and HTTP method.

## Basic Routing

EpicServer provides methods for all standard HTTP methods:

```go
server.GET("/users", GetUsers)
server.POST("/users", CreateUser)
server.PUT("/users/:id", UpdateUser)
server.DELETE("/users/:id", DeleteUser)
server.PATCH("/users/:id", PartialUpdateUser)
server.HEAD("/status", CheckStatus)
server.OPTIONS("/users", GetUserOptions)
```

## Route Parameters

You can define route parameters using the `:param` syntax:

```go
server.GET("/users/:id", func(ctx *epicserver.Context) {
    id := ctx.Param("id")
    // Use the id parameter
    ctx.String(http.StatusOK, "User ID: %s", id)
})
```

## Route Groups

Route groups allow you to organize routes and apply middleware to specific groups:

```go
// Create an API group
api := server.Group("/api")

// Apply middleware to all routes in this group
api.Use(AuthMiddleware())

// Define routes within the group
api.GET("/users", GetUsers)
api.POST("/users", CreateUser)

// Create a nested group
v1 := api.Group("/v1")
v1.GET("/products", GetProductsV1)
```

## Query Parameters

You can access query parameters using the `Query` method:

```go
server.GET("/search", func(ctx *epicserver.Context) {
    query := ctx.Query("q")
    page := ctx.DefaultQuery("page", "1")
    
    // Use the query parameters
    ctx.JSON(http.StatusOK, gin.H{
        "query": query,
        "page": page,
    })
})
```

## Wildcard Routes

EpicServer supports wildcard routes for matching multiple path segments:

```go
server.GET("/static/*filepath", func(ctx *epicserver.Context) {
    filepath := ctx.Param("filepath")
    // Serve static file from filepath
})
```

## Custom HTTP Methods

You can handle custom HTTP methods using the `Handle` method:

```go
server.Handle("PROPFIND", "/resources", HandlePropFind)
```

## Best Practices

1. **Organize Routes**: Use route groups to keep your code organized and apply middleware consistently.
2. **Descriptive Names**: Use descriptive route paths that reflect your resource hierarchy.
3. **Versioning**: Consider versioning your API routes (e.g., `/api/v1/users`).
4. **RESTful Design**: Follow RESTful principles when designing your API endpoints.
5. **Error Handling**: Implement consistent error handling across your routes. 