---
title: "Server Architecture"
description: "Understand the architecture of EpicServer."
summary: "Deep dive into the architecture of EpicServer and how its components work together."
date: 2023-09-07T16:06:50+02:00
lastmod: 2023-09-07T16:06:50+02:00
draft: false
weight: 10
toc: true
seo:
  title: "EpicServer Architecture" # custom title (optional)
  description: "Comprehensive explanation of EpicServer's architecture and component interaction." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Overview

EpicServer is built on top of the Gin framework, providing a powerful and flexible foundation for web applications and APIs. The architecture of EpicServer is designed to be modular, extensible, and easy to understand.

## High-Level Architecture

At a high level, EpicServer's architecture consists of the following components:

1. **Server Core**: Manages the HTTP server and its lifecycle
2. **Router**: Manages route registration and dispatching
3. **Middleware**: Processes requests before they reach handlers
4. **Context**: Encapsulates request and response
5. **Logger**: Provides structured logging
6. **Configuration**: Manages server configuration

These components work together to provide a robust foundation for web applications.

```
┌─────────────────────────────────────────────────────┐
│                  EpicServer                          │
│                                                     │
│  ┌─────────┐    ┌─────────┐    ┌─────────────────┐  │
│  │  Router │    │ Context │    │ Middleware Chain│  │
│  └─────────┘    └─────────┘    └─────────────────┘  │
│        │             │                │             │
│        └─────────────┼────────────────┘             │
│                      │                              │
│                      ▼                              │
│  ┌─────────┐    ┌─────────┐    ┌─────────────────┐  │
│  │  Logger │    │  Server │    │   Configuration │  │
│  └─────────┘    └─────────┘    └─────────────────┘  │
│                                                     │
└─────────────────────────────────────────────────────┘
           │                │
           ▼                ▼
┌─────────────────┐  ┌─────────────────┐
│   HTTP Client   │  │   Database      │
└─────────────────┘  └─────────────────┘
```

## Server Core

The Server Core is responsible for initializing and managing the HTTP server. It handles:

- Server lifecycle (start, stop, graceful shutdown)
- Configuration application
- Middleware registration
- Route registration

The Server Core is thread-safe, using mutexes to protect concurrent access to shared resources.

## Router

The Router component is responsible for:

- Registering routes with HTTP methods (GET, POST, PUT, etc.)
- Creating route groups
- Parsing URL parameters
- Dispatching requests to the appropriate handler

EpicServer's router is built on top of Gin's router, which uses a radix tree for efficient route matching.

## Middleware

Middleware functions process requests before they reach the handler, or after the response is generated. They form a chain, where each middleware can:

- Modify the request
- Short-circuit the request processing
- Pass control to the next middleware
- Modify the response

Common middleware provided by EpicServer include:

- Logging
- Recovery from panics
- CORS support
- Authentication
- Rate limiting

## Context

The Context encapsulates the HTTP request and response, providing methods to:

- Access request data (parameters, body, headers)
- Set and get values in the request context
- Send responses (JSON, HTML, XML, etc.)
- Handle errors

The Context is passed to all middleware and handlers, providing a consistent interface for request processing.

## Logger

EpicServer provides a structured logger that:

- Supports multiple log levels (DEBUG, INFO, WARN, ERROR)
- Outputs logs in various formats (text, JSON)
- Allows attaching structured fields to log entries
- Can be configured for different environments

## Configuration

The Configuration component manages server settings, including:

- Server address and port
- Timeouts (read, write, idle)
- TLS settings
- Logger configuration
- Middleware configuration

## Request Lifecycle

1. **Client Request**: A client sends an HTTP request to the server
2. **Server Receives Request**: The HTTP server accepts the connection and passes the request to the router
3. **Middleware Processing**: The request passes through the middleware chain
4. **Route Matching**: The router matches the request to a registered route
5. **Handler Execution**: The matched handler is executed
6. **Response Generation**: The handler generates a response
7. **Middleware Post-Processing**: The response passes back through the middleware chain
8. **Server Sends Response**: The HTTP server sends the response back to the client

## Extending EpicServer

EpicServer is designed to be extensible through:

1. **Custom Middleware**: Create your own middleware functions
2. **Custom Handlers**: Implement your own route handlers
3. **Configuration Extensions**: Extend the configuration structure
4. **Hooks**: Use lifecycle hooks to add custom behavior 