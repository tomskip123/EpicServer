---
title: "Quick Start"
description: "Get up and running with EpicServer in minutes."
summary: "A step-by-step guide to create your first EpicServer application."
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 20
toc: true
seo:
  title: "EpicServer Quick Start Guide" # custom title (optional)
  description: "Learn how to quickly set up and run an EpicServer application in minutes." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

This quick start guide will help you create a simple web server using EpicServer. By the end, you'll have a working HTTP server with basic routing and logging.

## Create a New Project

First, create a new directory for your project and initialize a Go module:

```bash
mkdir myepicserver
cd myepicserver
go mod init myepicserver
```

## Install EpicServer

Add EpicServer to your project:

```bash
go get github.com/tomskip123/EpicServer/v2
```

## Create a Basic Server

Create a file named `main.go` with the following content:

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

This creates a minimal server with a health check endpoint and sets the environment to development.

## Complete Example

Here's a more complete example with routing, database, and authentication:

```go
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/tomskip123/EpicServer/v2"
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

## Run Your Server

Run your server with:

```bash
go run main.go
```

Visit `http://localhost:8080/health` in your browser or use curl to check if your server is running:

```bash
curl http://localhost:8080/health
```

You should see a response indicating the server is healthy.

## Next Steps

Now that you have a basic server running, you can:

1. Learn about [Routing](../../guides/routing/) to add more endpoints
2. Set up [Middleware](../../guides/middleware/) for request processing
3. Explore [Database Support](../../guides/database/) for your application
4. Implement [Authentication](../../guides/authentication/) for secure access 