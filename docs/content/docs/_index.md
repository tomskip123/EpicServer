---
title: "EpicServer Documentation"
description: "Documentation for EpicServer, a powerful, flexible, and production-ready Go web server built on top of Gin framework."
summary: "Complete documentation for the EpicServer Go web framework."
date: 2023-09-07T16:12:03+02:00
lastmod: 2023-09-07T16:12:03+02:00
draft: false
weight: 999
toc: true
seo:
  title: "EpicServer Documentation" # custom title (optional)
  description: "Official documentation for EpicServer, a powerful and flexible Go web server built on top of the Gin framework." # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
---

# EpicServer

> A powerful, flexible, and production-ready Go web server built on top of Gin framework.

**Go Version:** >=1.16 | **Current Version:** 2.0.3 | [**Coverage Status**](https://coveralls.io/github/tomskip123/EpicServer?branch=main&v=1)

## 📥 Installation

```bash
go get github.com/tomskip123/EpicServer/v2
```

> **Note:** Version 2.x is the only supported version. Version 1.x is deprecated and should not be used for new projects.

## ⚠️ Breaking Changes in v2.0.0

Version 2.0.0 introduces significant improvements with breaking changes. See [CHANGELOG.md](https://github.com/tomskip123/EpicServer/blob/main/CHANGELOG.md) for details and migration guide.

Key changes:
- Structured logging replaces variadic logging
- Database connections now return errors instead of panicking
- Enhanced configuration system with validation
- Improved security features

## 📝 Enhanced Documentation in v2.0.1

Version 2.0.1 improves documentation with:
- Detailed migration guide with code examples
- Comprehensive API usage examples
- Improved integration examples with imports and context
- Enhanced changelog maintenance

## 🧪 Enhanced Test Coverage in v2.0.3

Version 2.0.3 improves test coverage and reliability:
- Improved overall test coverage to 80.7%, surpassing the minimum threshold of 80%
- Added comprehensive tests for CSRF protection functionality
- Enhanced logging test suite with additional test cases
- Fixed edge cases in authentication tests
- Added specific tests for middleware components

## 🔧 Recent Improvements in Unreleased Version

- **Thread Safety Improvements**:
  - Fixed data race condition in Server struct by adding a mutex to protect concurrent access
  - Updated `Start()` and `Stop()` methods to use mutex protection when accessing the HTTP server
  - Enhanced tests to properly handle concurrent access to server resources

Welcome to the official documentation for EpicServer, a powerful, flexible, and production-ready Go web server built on top of the Gin framework. This documentation will help you get started with EpicServer and provide detailed information on its features and capabilities.
