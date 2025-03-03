---
title: "Installation"
description: "How to install EpicServer in your Go project."
summary: "Learn how to add EpicServer to your Go project using Go modules."
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 10
toc: true
seo:
  title: "Installing EpicServer" # custom title (optional)
  description: "Step-by-step guide to install EpicServer in your Go project." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

## Prerequisites

Before installing EpicServer, ensure you have:

- Go 1.16 or later installed
- A Go project initialized with Go modules

## Installation

Add EpicServer to your project using Go modules:

```bash
go get -u github.com/tomskip123/EpicServer
```

This will install the latest version of EpicServer in your project.

## Verify Installation

Verify the installation by checking your `go.mod` file. You should see EpicServer listed among your dependencies:

```go
require (
    github.com/tomskip123/EpicServer v2.0.3
    // other dependencies
)
```

## Next Steps

After installation, you can:

1. Follow the [Quick Start Guide](../quick-start/) to set up a basic server
2. Learn about [Core Concepts](../../concepts/overview/) to understand EpicServer's architecture
3. Explore [Examples](../../examples/basic-server/) to see EpicServer in action 