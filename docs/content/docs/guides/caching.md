---
title: "Caching"
description: "Learn how to use caching in EpicServer."
summary: "A comprehensive guide to implementing caching in EpicServer."
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 50
toc: true
seo:
  title: "EpicServer Caching Guide" # custom title (optional)
  description: "Learn how to implement in-memory and Redis caching in EpicServer." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Caching in EpicServer

EpicServer provides built-in caching support with both in-memory and Redis cache providers. This guide will show you how to configure and use caching in your applications.

### Setting Up In-Memory Cache

The in-memory cache is the simplest way to add caching to your application:

```go
package main

import (
    "github.com/tomskip123/EpicServer/v2"
)

func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // Configure in-memory cache
            EpicServer.WithMemoryCache(&EpicServer.MemoryCacheConfig{
                DefaultExpiration: 5 * time.Minute,
                CleanupInterval:   10 * time.Minute,
                ConnectionName:    "default",
            }),
        },
    })

    server.Start()
}
```

### Setting Up Redis Cache

For distributed applications, Redis cache is recommended:

```go
package main

import (
    "github.com/tomskip123/EpicServer/v2"
)

func main() {
    server := EpicServer.NewServer(&EpicServer.NewServerParam{
        AppLayer: []EpicServer.AppLayer{
            // Configure Redis cache
            EpicServer.WithRedisCache(&EpicServer.RedisCacheConfig{
                ConnectionName: "default",
                Address:        "localhost:6379",
                Password:      "",
                DB:            0,
            }),
        },
    })

    server.Start()
}
```

### Multiple Cache Connections

You can configure multiple cache connections with different names:

```go
// Configure multiple cache connections
server.UpdateAppLayer([]EpicServer.AppLayer{
    // In-memory cache for session data
    EpicServer.WithMemoryCache(&EpicServer.MemoryCacheConfig{
        DefaultExpiration: 30 * time.Minute,
        CleanupInterval:   1 * time.Hour,
        ConnectionName:    "sessions",
    }),
    
    // Redis cache for API responses
    EpicServer.WithRedisCache(&EpicServer.RedisCacheConfig{
        ConnectionName: "api",
        Address:        "localhost:6379",
        Password:      "",
        DB:            1,
    }),
})
```

## Using Cache in Your Application

### Basic Cache Operations

```go
// Get cache client
cache, err := server.GetCache("default")
if err != nil {
    // Handle error
}

// Set a value with default expiration
err = cache.Set("key", "value", 0)
if err != nil {
    // Handle error
}

// Set a value with custom expiration
err = cache.Set("key", "value", 5*time.Minute)
if err != nil {
    // Handle error
}

// Get a value
var value string
found, err := cache.Get("key", &value)
if err != nil {
    // Handle error
}
if found {
    // Use value
}

// Delete a value
err = cache.Delete("key")
if err != nil {
    // Handle error
}
```

### Caching in Route Handlers

```go
func GetUserHandler(c *gin.Context, s *EpicServer.Server) {
    userID := c.Param("id")
    cacheKey := "user:" + userID
    
    // Try to get from cache first
    cache, _ := s.GetCache("default")
    var user User
    found, _ := cache.Get(cacheKey, &user)
    
    if found {
        // Return cached user
        c.JSON(200, user)
        return
    }
    
    // Get from database if not in cache
    collection, _ := EpicServerDb.GetMongoCollection(s, "default", "myapp", "users")
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    objectID, _ := primitive.ObjectIDFromHex(userID)
    err := collection.FindOne(ctx, bson.M{"_id": objectID}).Decode(&user)
    if err != nil {
        c.JSON(404, gin.H{"error": "User not found"})
        return
    }
    
    // Store in cache for future requests
    cache.Set(cacheKey, user, 5*time.Minute)
    
    // Return user
    c.JSON(200, user)
}
```

### Cache Invalidation

```go
func UpdateUserHandler(c *gin.Context, s *EpicServer.Server) {
    userID := c.Param("id")
    var updateData User
    
    if err := c.ShouldBindJSON(&updateData); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    
    // Update in database
    collection, _ := EpicServerDb.GetMongoCollection(s, "default", "myapp", "users")
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    objectID, _ := primitive.ObjectIDFromHex(userID)
    update := bson.M{
        "$set": bson.M{
            "name":       updateData.Name,
            "updated_at": time.Now(),
        },
    }
    
    _, err := collection.UpdateOne(ctx, bson.M{"_id": objectID}, update)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to update user"})
        return
    }
    
    // Invalidate cache
    cache, _ := s.GetCache("default")
    cache.Delete("user:" + userID)
    
    c.JSON(200, gin.H{"message": "User updated successfully"})
}
```

## Advanced Caching Techniques

### Caching with TTL (Time-To-Live)

```go
// Cache with 1 hour TTL
cache.Set("long-lived-data", data, time.Hour)

// Cache with 30 seconds TTL
cache.Set("short-lived-data", data, 30*time.Second)

// Cache with default TTL (from config)
cache.Set("default-ttl-data", data, 0)
```

### Batch Operations

```go
// Get multiple values
keys := []string{"key1", "key2", "key3"}
values := make(map[string]interface{})

for _, key := range keys {
    var value interface{}
    found, _ := cache.Get(key, &value)
    if found {
        values[key] = value
    }
}

// Delete multiple values
for _, key := range keys {
    cache.Delete(key)
}
```

### Caching Complex Objects

```go
type ComplexObject struct {
    ID        string
    Name      string
    CreatedAt time.Time
    Data      map[string]interface{}
    Items     []Item
}

type Item struct {
    ID    string
    Value int
}

// Cache complex object
obj := ComplexObject{
    ID:        "123",
    Name:      "Test Object",
    CreatedAt: time.Now(),
    Data: map[string]interface{}{
        "key1": "value1",
        "key2": 42,
    },
    Items: []Item{
        {ID: "item1", Value: 10},
        {ID: "item2", Value: 20},
    },
}

cache.Set("complex:123", obj, time.Hour)

// Retrieve complex object
var retrieved ComplexObject
found, _ := cache.Get("complex:123", &retrieved)
if found {
    // Use retrieved object
}
```

## Complete Caching Example

Here's a complete example with Redis cache and MongoDB integration:

```go
package main

import (
    "context"
    "encoding/json"
    "time"
    
    "github.com/gin-gonic/gin"
    "github.com/tomskip123/EpicServer/v2"
    "github.com/tomskip123/EpicServer/db"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/bson/primitive"
)

// Product model
type Product struct {
    ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    Name        string             `bson:"name" json:"name"`
    Description string             `bson:"description" json:"description"`
    Price       float64            `bson:"price" json:"price"`
    CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
    UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

func main() {
    // Initialize server
    server := EpicServer.NewServer([]EpicServer.Option{
        EpicServer.SetHost("localhost", 8080),
    })
    
    // Configure server
    server.UpdateAppLayer([]EpicServer.AppLayer{
        // Add MongoDB connection
        EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
            ConnectionName: "default",
            URI:           "mongodb://localhost:27017",
            DatabaseName:  "myapp",
        }),
        
        // Add Redis cache
        EpicServer.WithRedisCache(&EpicServer.RedisCacheConfig{
            ConnectionName: "default",
            Address:        "localhost:6379",
            Password:      "",
            DB:            0,
        }),
        
        // Add routes
        EpicServer.WithRoutes(
            EpicServer.RouteGroup{
                Prefix: "/api/v1",
                Routes: []EpicServer.Route{
                    EpicServer.Get("/products", GetProducts),
                    EpicServer.Get("/products/:id", GetProduct),
                    EpicServer.Post("/products", CreateProduct),
                    EpicServer.Put("/products/:id", UpdateProduct),
                    EpicServer.Delete("/products/:id", DeleteProduct),
                },
            },
        ),
    })
    
    // Start the server
    server.Start()
}

// GetProducts returns all products with caching
func GetProducts(c *gin.Context, s *EpicServer.Server) {
    cacheKey := "products:all"
    
    // Try to get from cache first
    cache, _ := s.GetCache("default")
    var productsJSON string
    found, _ := cache.Get(cacheKey, &productsJSON)
    
    if found {
        // Return cached products
        c.Header("X-Cache", "HIT")
        c.Data(200, "application/json", []byte(productsJSON))
        return
    }
    
    // Get from database if not in cache
    collection, _ := EpicServerDb.GetMongoCollection(s, "default", "myapp", "products")
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    cursor, err := collection.Find(ctx, bson.M{})
    if err != nil {
        c.JSON(500, gin.H{"error": "Database error"})
        return
    }
    defer cursor.Close(ctx)
    
    var products []Product
    if err := cursor.All(ctx, &products); err != nil {
        c.JSON(500, gin.H{"error": "Failed to decode products"})
        return
    }
    
    // Store in cache for future requests
    productsData, _ := json.Marshal(products)
    productsJSON = string(productsData)
    cache.Set(cacheKey, productsJSON, 5*time.Minute)
    
    // Return products
    c.Header("X-Cache", "MISS")
    c.Data(200, "application/json", productsData)
}

// GetProduct returns a single product with caching
func GetProduct(c *gin.Context, s *EpicServer.Server) {
    productID := c.Param("id")
    cacheKey := "product:" + productID
    
    // Try to get from cache first
    cache, _ := s.GetCache("default")
    var productJSON string
    found, _ := cache.Get(cacheKey, &productJSON)
    
    if found {
        // Return cached product
        c.Header("X-Cache", "HIT")
        c.Data(200, "application/json", []byte(productJSON))
        return
    }
    
    // Get from database if not in cache
    collection, _ := EpicServerDb.GetMongoCollection(s, "default", "myapp", "products")
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    objectID, err := primitive.ObjectIDFromHex(productID)
    if err != nil {
        c.JSON(400, gin.H{"error": "Invalid product ID"})
        return
    }
    
    var product Product
    err = collection.FindOne(ctx, bson.M{"_id": objectID}).Decode(&product)
    if err != nil {
        c.JSON(404, gin.H{"error": "Product not found"})
        return
    }
    
    // Store in cache for future requests
    productData, _ := json.Marshal(product)
    productJSON = string(productData)
    cache.Set(cacheKey, productJSON, 5*time.Minute)
    
    // Return product
    c.Header("X-Cache", "MISS")
    c.Data(200, "application/json", productData)
}

// CreateProduct creates a new product and invalidates cache
func CreateProduct(c *gin.Context, s *EpicServer.Server) {
    var product Product
    
    if err := c.ShouldBindJSON(&product); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    
    // Set timestamps
    now := time.Now()
    product.CreatedAt = now
    product.UpdatedAt = now
    
    // Insert into database
    collection, _ := EpicServerDb.GetMongoCollection(s, "default", "myapp", "products")
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    result, err := collection.InsertOne(ctx, product)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to create product"})
        return
    }
    
    // Get the inserted ID
    product.ID = result.InsertedID.(primitive.ObjectID)
    
    // Invalidate cache
    cache, _ := s.GetCache("default")
    cache.Delete("products:all")
    
    c.JSON(201, product)
}

// UpdateProduct updates a product and invalidates cache
func UpdateProduct(c *gin.Context, s *EpicServer.Server) {
    productID := c.Param("id")
    var updateData Product
    
    if err := c.ShouldBindJSON(&updateData); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    
    // Update in database
    collection, _ := EpicServerDb.GetMongoCollection(s, "default", "myapp", "products")
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    objectID, err := primitive.ObjectIDFromHex(productID)
    if err != nil {
        c.JSON(400, gin.H{"error": "Invalid product ID"})
        return
    }
    
    update := bson.M{
        "$set": bson.M{
            "name":        updateData.Name,
            "description": updateData.Description,
            "price":       updateData.Price,
            "updated_at":  time.Now(),
        },
    }
    
    _, err = collection.UpdateOne(ctx, bson.M{"_id": objectID}, update)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to update product"})
        return
    }
    
    // Invalidate cache
    cache, _ := s.GetCache("default")
    cache.Delete("products:all")
    cache.Delete("product:" + productID)
    
    c.JSON(200, gin.H{"message": "Product updated successfully"})
}

// DeleteProduct deletes a product and invalidates cache
func DeleteProduct(c *gin.Context, s *EpicServer.Server) {
    productID := c.Param("id")
    
    // Delete from database
    collection, _ := EpicServerDb.GetMongoCollection(s, "default", "myapp", "products")
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    objectID, err := primitive.ObjectIDFromHex(productID)
    if err != nil {
        c.JSON(400, gin.H{"error": "Invalid product ID"})
        return
    }
    
    _, err = collection.DeleteOne(ctx, bson.M{"_id": objectID})
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to delete product"})
        return
    }
    
    // Invalidate cache
    cache, _ := s.GetCache("default")
    cache.Delete("products:all")
    cache.Delete("product:" + productID)
    
    c.JSON(200, gin.H{"message": "Product deleted successfully"})
}
``` 