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
go get -u github.com/tomskip123/EpicServer
```

## Create a Basic Server

Create a file named `main.go` with the following content:

```go
package main

import (
	"github.com/tomskip123/EpicServer"
	"log"
	"net/http"
)

func main() {
	// Create a new server with default configuration
	server := epicserver.NewServer(&epicserver.Config{
		Port:         8080,
		ReadTimeout:  30,
		WriteTimeout: 30,
	})

	// Add a simple route
	server.GET("/hello", func(ctx *epicserver.Context) {
		ctx.String(http.StatusOK, "Hello, EpicServer!")
	})

	// Start the server
	log.Println("Server starting on :8080...")
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
```

## Run Your Server

Run your server with:

```bash
go run main.go
```

Visit `http://localhost:8080/hello` in your browser or use curl:

```bash
curl http://localhost:8080/hello
```

You should see the message "Hello, EpicServer!".

## Next Steps

Now that you have a basic server running, you can:

1. Learn about [Routing](../../guides/routing/) to add more endpoints
2. Set up [Middleware](../../guides/middleware/) for request processing
3. Implement [Authentication](../../guides/authentication/) for your application 