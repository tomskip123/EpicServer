---
title: "Database Support"
description: "Learn how to use database adapters in EpicServer."
summary: "A comprehensive guide to using different database adapters in EpicServer."
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 30
toc: true
seo:
  title: "EpicServer Database Guide" # custom title (optional)
  description: "Learn how to use MongoDB, PostgreSQL, MySQL, and GORM database adapters in EpicServer." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Database Support in EpicServer

EpicServer supports multiple database adapters out of the box, allowing you to connect to various database systems.

### MongoDB

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

### PostgreSQL

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

### MySQL

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

### GORM

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
        Port:          5432,
        User:          "postgres",
        Password:      "password",
        Database:      "products",
        SSLMode:       "disable",
    }),
    EpicServerDb.WithMySQL(EpicServerDb.MySQLConfig{
        ConnectionName: "orders",
        Host:          "localhost",
        Port:          3306,
        User:          "root",
        Password:      "password",
        Database:      "orders",
    }),
})
```

### Error Handling

In EpicServer v2.0.0 and later, database connections return errors instead of panicking:

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
    c.JSON(500, gin.H{"error": "Failed to access collection"})
    return
}
```

### Database Helper Functions

EpicServer provides several helper functions for working with databases:

#### MongoDB Helpers

```go
// Convert string to MongoDB ObjectID
id := EpicServerDb.StringToObjectID("5f8a7b6c5d4e3f2a1b0c9d8e")

// Convert string array to ObjectID array
ids := EpicServerDb.StringArrayToObjectIDArray([]string{"5f8a7b6c5d4e3f2a1b0c9d8e", "5f8a7b6c5d4e3f2a1b0c9d8f"})

// Create or update collection indexes
indexes := []mongo.IndexModel{
    {
        Keys:    bson.D{{Key: "email", Value: 1}},
        Options: options.Index().SetUnique(true),
    },
}
err := EpicServerDb.UpdateIndexes(ctx, collection, indexes)
```

#### GORM Helpers

```go
// Auto migrate models
err := EpicServerDb.AutoMigrateModels(s, "default", &User{}, &Product{}, &Order{})
if err != nil {
    // Handle error
}
``` 