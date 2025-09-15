# EpicServer

EpicServer is a minimal, standard-library-first toolkit for building Go web apps that can serve HTML and JSON without a heavy framework. It wraps `http.ServeMux`, `html/template`, and a handful of helper functions so you can focus on routing, rendering, and responses instead of the surrounding plumbing.

## Features

- Chainable server builder (`epicserver.New`) with middleware wiring and graceful shutdown.
- Declarative router with method helpers, route grouping, and duplicate route detection before start-up.
- HTMX-aware template rendering with conventions for layouts, components, and pages.
- Request helpers for binding JSON, reading bodies safely, and parsing query/header values.
- Response helpers for JSON, HTML, text, streaming, file downloads, and cookie management.
- Simple middleware interface (`type Middleware func(http.Handler) http.Handler`) compatible with the Go standard library.

## Installation

```bash
go get github.com/tomskip123/EpicServer
```

Requires Go 1.24 or newer (matches `go.mod`).

## Quick Start

```go
package main

import (
    "log"
    "net/http"

    epicserver "github.com/tomskip123/EpicServer"
)

func main() {
    srv := epicserver.New().
        Use(logging()).
        Routes(func(r *epicserver.RouteBuilder) {
            r.Get("/", func(w http.ResponseWriter, r *http.Request) {
                _ = epicserver.HTML(w, http.StatusOK, "<h1>Hello, EpicServer!</h1>")
            })

            r.Post("/api/widgets", func(w http.ResponseWriter, r *http.Request) {
                var req createWidgetRequest
                if err := epicserver.BindJSONStrict(r, &req); err != nil {
                    _ = epicserver.ErrorJSON(w, http.StatusBadRequest, err.Error())
                    return
                }
                _ = epicserver.JSON(w, http.StatusCreated, epicserver.H{"widget": req})
            })
        })

    if err := srv.Start(); err != nil {
        log.Fatal(err)
    }
}

func logging() epicserver.Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            log.Printf("%s %s", r.Method, r.URL.Path)
            next.ServeHTTP(w, r)
        })
    }
}

type createWidgetRequest struct {
    Name string `json:"name"`
}
```

`Start` listens on `localhost:8080` and shuts down cleanly when `SIGINT`/`SIGTERM` is received.

## Routing

Define routes inside `Routes` to register handlers on the shared `ServeMux`:

```go
srv.Routes(func(r *epicserver.RouteBuilder) {
    r.Get("/healthz", healthHandler)

    r.Group("/admin", func(admin *epicserver.RouteBuilder) {
        admin.Use(authMiddleware)
        admin.Get("/users", listUsers)
        admin.Post("/users", createUser)
    })
})
```

Supported helpers include `Get`, `Post`, `Put`, `Patch`, `Delete`, and `Any`. Re-registering the same method/path is flagged before the server starts, helping you catch accidental duplicates. Middleware added with `RouteBuilder.Use` applies to that builder (including nested groups).

## Views & Templates

The `View` type wraps `html/template` and introduces a simple structure compatible with HTMX:

```go
views := srv.View(
    epicserver.WithBaseDir("templates"),
    epicserver.WithDev(true), // reload templates on each request during development
)

views.MountGet("/", "home", func(r *http.Request) any {
    return epicserver.H{"Title": "Welcome"}
})
```

Default template layout:

```
templates/
  layouts/base.html       // defines {{define "base"}} ... {{end}}
  components/nav.html     // defines {{define "components/nav"}} ... {{end}}
  pages/home.html         // defines {{define "content"}} ... {{end}}
```

On HTMX requests (header `HX-Request: true` and not boosted), only the `content` block is rendered; otherwise the full layout (`LayoutName`, default `"base"`) is executed. Map-like data passed to `Render` automatically gets an `HX` field containing request metadata. Built-in template funcs include `concat`, `attr`, and `partial` for composing HTML snippets.

## HTMX Response Helpers

Manipulate HTMX behaviour with helpers that set the appropriate response headers:

- `HXRedirect`, `HXLocation`, `HXPushURL`, `HXReplaceURL`
- `HXReswap`, `HXRetarget`
- `HXTrigger`, `HXTriggerAfterSwap`, `HXTriggerAfterSettle`
- `HXRefresh`

## Request Helpers

Utilities for working with `*http.Request` values:

- `BindJSON`, `BindJSONStrict` (and `WithLimit` variants) decode request JSON with content type checks and sane size limits (default 1 MiB).
- `ReadBody`, `BodyText` safely read request bodies.
- Query helpers: `Query`, `QueryDefault`, `QueryAll`, `QueryInt`, `QueryBool`.
- Header helpers: `Header`, `HasHeader`, `BearerToken`, `ContentType`, `IsJSON`.
- `ClientIP` extracts a best-effort client IP from common proxy headers.

## Response Helpers

Helpers for consistent responses:

- `JSON`, `ErrorJSON`, `HTML`, `Text`, `Bytes`, `Stream` handle headers and body writing.
- `File` and `Download` for serving assets or forcing downloads.
- `Redirect`, `NoContent`, `SetCookie`, `ClearCookie` for common operations.

Use `epicserver.H`, `Fields`, `Msg`, `Err`, `Envelope[T]`, `List[T]`, and `Page[T]` to shape JSON payloads quickly.

## Middleware

Middleware is simply `func(http.Handler) http.Handler`. Add global middleware with `EpicServerBuilder.Use` (applies to routes/views defined afterwards) or scope it to route groups and views via their `Use` methods.

## Project Layout

```
├── epicserver.go       // core builder and server start logic
├── route.go            // router builder and middleware wiring
├── view.go             // template renderer with HTMX helpers
├── request.go          // request parsing utilities
├── response.go         // response helpers
├── types.go            // shared helper types (H, Fields, envelopes, etc.)
├── middleware.go       // middleware type definition
├── config/             // placeholder for app-specific configuration
└── database/           // placeholder for data-layer integrations
```

## Next Steps

- Wire in your real routes, middleware, and views.
- Fill out `config/` and `database/` with application-specific logic.
- Add tests around handlers that rely on the helpers above to ensure the contract you want to maintain.

Happy hacking!
