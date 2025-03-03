# Changelog

All notable changes to EpicServer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.2] - 2024-03-03

### Improvements

- **Test Coverage Framework**:
  - Added comprehensive test coverage validation with reporting tools
  - Implemented `test-coverage.sh` script for generating detailed coverage reports
  - Added GitHub workflow for continuous test coverage validation in CI
  - Enhanced GitHub Actions workflow with Coveralls integration for visual coverage reporting
  - Set minimum coverage threshold at 80% with quality indicators
  - Added coverage configuration with `.coveragerc` for consistent analysis

### Bug Fixes

- **Thread Safety Improvements**:
  - Fixed data race condition in Server struct by adding a mutex to protect concurrent access to the `srv` field
  - Updated `Start()` and `Stop()` methods to use mutex protection when accessing the HTTP server
  - Enhanced tests to properly handle concurrent access to server resources

- **Test Improvements**:
  - Fixed `TestRateLimiterAllow` and `TestRateLimiterConcurrency` tests by implementing a simplified test-specific RateLimiter
  - Fixed `TestLogger_Levels` to properly set the debug log level before testing
  - Updated `TestNewServer` to check for errors using `HasErrors()` instead of expecting panics
  - Fixed `TestDefaultAuthHooks_OnUserCreate` and `TestDefaultHooks` to align with the updated implementation of `OnUserCreate`

## [2.0.1] - 2023-06-10

### Improvements

- **Documentation**:
  - Added detailed migration guide to README.md with code examples for all breaking changes
  - Enhanced code examples with imports and context for better clarity
  - Added complete API usage examples for new features in v2.0.0

- **AI Development Support**:
  - Added comprehensive cursor rules documentation for AI-assisted development
  - Implemented changelog maintenance guidelines to ensure consistent documentation
  - Added migration patterns with before/after code examples

## [2.0.0] - 2023-05-29

### Breaking Changes

- **Logger Interface**: Completely refactored the logging system
  - Logger interface now requires structured logging methods
  - Changed method signatures from `Debug(args ...interface{})` to `Debug(msg string, fields ...LogField)`
  - Added new methods: `WithFields()`, `SetOutput()`, `SetLevel()`, `SetFormat()`, and `Fatal()`
  - Migration: Update to use the new `F()` function for structured fields (e.g., `logger.Info("Message", F("key", value))`)

- **MongoDB Interface**:
  - `GetMongoClient()` now returns `(*mongo.Client, bool)` instead of just `*mongo.Client`
  - `GetMongoCollection()` now returns `(*mongo.Collection, error)` instead of just `*mongo.Collection`
  - Removed panic calls in database connections, now returns errors instead
  - Migration: Check the boolean/error return values before using the client or collection

- **Memory Cache Configuration**:
  - Added required configuration parameters for the memory cache
  - Migration: Set `DefaultTTL`, `CleanupInterval`, and optionally `MaxItems` when creating a memory cache

- **Server Initialization**:
  - Server no longer panics on configuration errors
  - You must check `server.HasErrors()` after initialization
  - Migration: Add error checks after server creation

### New Features

- **Structured Logging System**:
  - Added support for multiple log levels (Debug, Info, Warn, Error, Fatal)
  - Added structured log fields for better parsing and searching
  - Added different output formats (Text, JSON)
  - Added caller information for better debugging
  - Added log level configuration

- **Enhanced Configuration System**:
  - Added environment variable support via `WithEnvVars()` option
  - Implemented configuration validation via `Config.Validate()`
  - Added more configuration options for security settings
  - Created better defaults for secure configuration

- **Security Enhancements**:
  - Added comprehensive IP-based rate limiting with `WithRateLimiter()`
  - Added security headers middleware with `WithSecurityHeaders()`
  - Implemented HTTP Strict Transport Security (HSTS)
  - Added Content Security Policy (CSP) support
  - Added Referrer Policy and Permissions Policy
  - Added X-Content-Type-Options, X-Frame-Options, and X-XSS-Protection

- **Cache Improvements**:
  - Enhanced memory cache with TTL-based cleanup
  - Added cache eviction policies based on age
  - Added cache statistics
  - Added more cache operations (Flush, ItemCount)

### Improvements

- **Error Handling**:
  - Added custom error types for better error information
  - Added error tracking in the server for initialization errors
  - Added methods to check server initialization status and retrieve errors
  - Replaced panics with proper error returns

- **Documentation**:
  - Added comprehensive documentation for all public APIs
  - Improved parameter naming for better readability
  - Added usage examples for complex features

- **Performance**:
  - Implemented more efficient middleware options
  - Added memory optimization in caching layer
  - Improved handling of database connections

### Internal Changes

- Improved code organization and consistency
- Enhanced test coverage and reliability
- Standardized error handling patterns
- Added more validation for configuration values 
