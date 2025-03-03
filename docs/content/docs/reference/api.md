---
title: "API Reference"
description: "Complete API reference for EpicServer."
summary: "Detailed documentation of all EpicServer's public API methods and types."
date: 2023-09-07T16:06:50+02:00
lastmod: 2023-09-07T16:06:50+02:00
draft: false
weight: 10
toc: true
seo:
  title: "EpicServer API Reference" # custom title (optional)
  description: "Complete API reference for all EpicServer's public methods, types, and interfaces." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Server

### NewServer

```go
func NewServer(config *Config) *Server
```

Creates a new EpicServer instance with the provided configuration.

**Parameters:**
- `config` - The server configuration. If nil, default configuration is used.

**Returns:**
- A new `Server` instance.

**Example:**
```go
server := epicserver.NewServer(&epicserver.Config{
    Port:         8080,
    ReadTimeout:  30, // seconds
    WriteTimeout: 30, // seconds
})
```

### Server.Start

```go
func (s *Server) Start() error
```

Starts the HTTP server.

**Returns:**
- An error if the server fails to start.

**Example:**
```go
if err := server.Start(); err != nil {
    log.Fatalf("Server failed to start: %v", err)
}
```

### Server.Stop

```go
func (s *Server) Stop() error
```

Gracefully stops the HTTP server.

**Returns:**
- An error if the server fails to stop gracefully.

**Example:**
```go
if err := server.Stop(); err != nil {
    log.Printf("Error stopping server: %v", err)
}
```

### Server.GET, POST, PUT, DELETE, etc.

```go
func (s *Server) GET(path string, handlers ...HandlerFunc) IRoute
func (s *Server) POST(path string, handlers ...HandlerFunc) IRoute
func (s *Server) PUT(path string, handlers ...HandlerFunc) IRoute
func (s *Server) DELETE(path string, handlers ...HandlerFunc) IRoute
func (s *Server) PATCH(path string, handlers ...HandlerFunc) IRoute
func (s *Server) HEAD(path string, handlers ...HandlerFunc) IRoute
func (s *Server) OPTIONS(path string, handlers ...HandlerFunc) IRoute
```

Registers a route with the given HTTP method, path, and handlers.

**Parameters:**
- `path` - The URL path for the route.
- `handlers` - One or more handler functions for the route.

**Returns:**
- An `IRoute` instance that can be used for chaining.

**Example:**
```go
server.GET("/users", GetUsers)
server.POST("/users", CreateUser)
```

## Context

### Context.Param

```go
func (c *Context) Param(key string) string
```

Gets the value of a URL parameter.

**Parameters:**
- `key` - The name of the parameter.

**Returns:**
- The parameter value as a string.

**Example:**
```go
func GetUser(ctx *epicserver.Context) {
    id := ctx.Param("id")
    // ...
}
```

### Context.Query

```go
func (c *Context) Query(key string) string
```

Gets the value of a query parameter.

**Parameters:**
- `key` - The name of the parameter.

**Returns:**
- The parameter value as a string.

**Example:**
```go
func SearchUsers(ctx *epicserver.Context) {
    query := ctx.Query("q")
    // ...
}
```

### Context.DefaultQuery

```go
func (c *Context) DefaultQuery(key, defaultValue string) string
```

Gets the value of a query parameter, or a default value if the parameter is not present.

**Parameters:**
- `key` - The name of the parameter.
- `defaultValue` - The default value to return if the parameter is not present.

**Returns:**
- The parameter value as a string, or the default value.

**Example:**
```go
func GetUsers(ctx *epicserver.Context) {
    page := ctx.DefaultQuery("page", "1")
    // ...
}
```

### Context.Bind

```go
func (c *Context) Bind(obj any) error
```

Binds the request body to the given struct.

**Parameters:**
- `obj` - The struct to bind to.

**Returns:**
- An error if binding fails.

**Example:**
```go
func CreateUser(ctx *epicserver.Context) {
    var user User
    if err := ctx.Bind(&user); err != nil {
        ctx.AbortWithError(http.StatusBadRequest, err)
        return
    }
    // ...
}
```

### Context.JSON

```go
func (c *Context) JSON(code int, obj any)
```

Sends a JSON response.

**Parameters:**
- `code` - The HTTP status code.
- `obj` - The object to be serialized to JSON.

**Example:**
```go
func GetUser(ctx *epicserver.Context) {
    user := GetUserByID(ctx.Param("id"))
    ctx.JSON(http.StatusOK, user)
}
```

## Logger

### NewLogger

```go
func NewLogger(config *LoggerConfig) *Logger
```

Creates a new structured logger.

**Parameters:**
- `config` - The logger configuration.

**Returns:**
- A new `Logger` instance.

**Example:**
```go
logger := epicserver.NewLogger(&epicserver.LoggerConfig{
    Level:  epicserver.LogLevelInfo,
    Format: epicserver.LogFormatJSON,
})
```

### Logger.Info, Error, Debug, etc.

```go
func (l *Logger) Info(msg string, fields ...Field)
func (l *Logger) Error(msg string, fields ...Field)
func (l *Logger) Debug(msg string, fields ...Field)
func (l *Logger) Warn(msg string, fields ...Field)
```

Logs a message at the specified level with optional fields.

**Parameters:**
- `msg` - The log message.
- `fields` - Optional fields to include in the log entry.

**Example:**
```go
logger.Info("User created", 
    epicserver.String("user_id", "123"),
    epicserver.Int("status", 201),
)
```

## Configuration

### Config

```go
type Config struct {
    Port           int
    ReadTimeout    int
    WriteTimeout   int
    IdleTimeout    int
    MaxHeaderBytes int
    // other fields...
}
```

Configuration for the EpicServer.

**Fields:**
- `Port` - The port to listen on.
- `ReadTimeout` - The maximum duration for reading the entire request, including the body.
- `WriteTimeout` - The maximum duration before timing out writes of the response.
- `IdleTimeout` - The maximum amount of time to wait for the next request when keep-alives are enabled.
- `MaxHeaderBytes` - The maximum number of bytes the server will read parsing the request header. 