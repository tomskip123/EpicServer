---
title: "Basic API Server"
description: "Build a basic RESTful API server with EpicServer."
summary: "Step-by-step guide to create a simple RESTful API using EpicServer."
date: 2023-09-07T16:06:50+02:00
lastmod: 2023-09-07T16:06:50+02:00
draft: false
weight: 10
toc: true
seo:
  title: "Building a Basic API with EpicServer" # custom title (optional)
  description: "Learn how to build a RESTful API with CRUD operations using EpicServer." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Introduction

In this example, we'll build a simple RESTful API for managing tasks. Our API will support the following operations:

- Get all tasks
- Get a task by ID
- Create a new task
- Update a task
- Delete a task

## Project Setup

First, create a new directory for your project and initialize a Go module:

```bash
mkdir task-api
cd task-api
go mod init task-api
```

Install EpicServer:

```bash
go get -u github.com/tomskip123/EpicServer
```

## Define the Task Model

Create a file named `models.go` with the following content:

```go
package main

import "time"

type Task struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Completed   bool      `json:"completed"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// In-memory store for tasks
var tasks = make(map[string]*Task)
```

## Create API Handlers

Create a file named `handlers.go` with the following content:

```go
package main

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/tomskip123/EpicServer"
)

// GetTasks returns all tasks
func GetTasks(ctx *epicserver.Context) {
	// Convert map to slice for JSON response
	taskList := make([]*Task, 0, len(tasks))
	for _, task := range tasks {
		taskList = append(taskList, task)
	}
	
	ctx.JSON(http.StatusOK, taskList)
}

// GetTask returns a task by ID
func GetTask(ctx *epicserver.Context) {
	id := ctx.Param("id")
	
	task, exists := tasks[id]
	if !exists {
		ctx.JSON(http.StatusNotFound, epicserver.H{
			"error": "Task not found",
		})
		return
	}
	
	ctx.JSON(http.StatusOK, task)
}

// CreateTask creates a new task
func CreateTask(ctx *epicserver.Context) {
	var taskInput struct {
		Title       string `json:"title" binding:"required"`
		Description string `json:"description"`
	}
	
	if err := ctx.Bind(&taskInput); err != nil {
		ctx.JSON(http.StatusBadRequest, epicserver.H{
			"error": "Invalid input",
		})
		return
	}
	
	now := time.Now()
	task := &Task{
		ID:          uuid.New().String(),
		Title:       taskInput.Title,
		Description: taskInput.Description,
		Completed:   false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	
	tasks[task.ID] = task
	
	ctx.JSON(http.StatusCreated, task)
}

// UpdateTask updates an existing task
func UpdateTask(ctx *epicserver.Context) {
	id := ctx.Param("id")
	
	task, exists := tasks[id]
	if !exists {
		ctx.JSON(http.StatusNotFound, epicserver.H{
			"error": "Task not found",
		})
		return
	}
	
	var taskInput struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Completed   bool   `json:"completed"`
	}
	
	if err := ctx.Bind(&taskInput); err != nil {
		ctx.JSON(http.StatusBadRequest, epicserver.H{
			"error": "Invalid input",
		})
		return
	}
	
	// Update fields if provided
	if taskInput.Title != "" {
		task.Title = taskInput.Title
	}
	
	if taskInput.Description != "" {
		task.Description = taskInput.Description
	}
	
	task.Completed = taskInput.Completed
	task.UpdatedAt = time.Now()
	
	ctx.JSON(http.StatusOK, task)
}

// DeleteTask deletes a task
func DeleteTask(ctx *epicserver.Context) {
	id := ctx.Param("id")
	
	_, exists := tasks[id]
	if !exists {
		ctx.JSON(http.StatusNotFound, epicserver.H{
			"error": "Task not found",
		})
		return
	}
	
	delete(tasks, id)
	
	ctx.JSON(http.StatusNoContent, nil)
}
```

## Create Main Application

Create a file named `main.go` with the following content:

```go
package main

import (
	"log"

	"github.com/tomskip123/EpicServer"
)

func main() {
	// Create a new server with default configuration
	server := epicserver.NewServer(&epicserver.Config{
		Port:         8080,
		ReadTimeout:  30,
		WriteTimeout: 30,
	})

	// Add middleware
	server.Use(epicserver.Logger())
	server.Use(epicserver.Recovery())

	// Define API routes
	api := server.Group("/api")
	{
		tasks := api.Group("/tasks")
		{
			tasks.GET("", GetTasks)
			tasks.GET("/:id", GetTask)
			tasks.POST("", CreateTask)
			tasks.PUT("/:id", UpdateTask)
			tasks.DELETE("/:id", DeleteTask)
		}
	}

	// Start the server
	log.Println("API server starting on :8080...")
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
```

## Run the API Server

Run the server with:

```bash
go run .
```

## Test the API

You can test the API using curl or any API client like Postman:

### Create a Task

```bash
curl -X POST http://localhost:8080/api/tasks \
  -H "Content-Type: application/json" \
  -d '{"title":"Learn EpicServer","description":"Build a simple REST API with EpicServer"}'
```

### Get All Tasks

```bash
curl http://localhost:8080/api/tasks
```

### Get a Task by ID

```bash
curl http://localhost:8080/api/tasks/{task_id}
```

### Update a Task

```bash
curl -X PUT http://localhost:8080/api/tasks/{task_id} \
  -H "Content-Type: application/json" \
  -d '{"completed":true}'
```

### Delete a Task

```bash
curl -X DELETE http://localhost:8080/api/tasks/{task_id}
```

## Conclusion

You've built a basic RESTful API using EpicServer! This example demonstrates how to:

- Set up a server with EpicServer
- Define and organize routes
- Create handlers for CRUD operations
- Use middleware for logging and recovery
- Work with JSON requests and responses

This is just a starting point. You can extend this example by adding:

- Database integration (e.g., PostgreSQL, MongoDB)
- Authentication and authorization
- Input validation
- Error handling middleware
- Swagger documentation