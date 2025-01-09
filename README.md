# EpicServer

# Warning! - Very much work in process. Use at your own risk.

A robust server application built with modern best practices.

## Overview

EpicServer is a lightweight helper library built on top of Go Gin that makes starting up a WebServer easy by providing methods that give you access to underlying builder configuration! You have as much control as you want or as little as you want!

## Installation

```bash
# Clone the repository
go get github.com/tomskip123/EpicServer
```

## Features

* OAuth Configuration
* Clean Route Registration
* Customisable Behaviours
* Event Hooks for Database management on top.
* Built In Authentication management with Cookies
* Opt-in Features following the WithFeature methods
* Cache Adapters.
* Database Adapters.

* For features like Cache and Databases, we only provide instances that accessible through helper functions like

```go
import (
	"context"
	"os"
	"time"
	
	"github.com/tomskip123/EpicServer"
	EpicServerCache "github.com/tomskip123/EpicServer/cache"
	EpicServerDb "github.com/tomskip123/EpicServer/db"
	"go.mongodb.org/mongo-driver/bson"
)

var (
	UserCachename = "user_cache"
)

// Example of getting a MemoryCache
userMemoryCache := EpicServerCache.GetMemoryCache(s, UserCachename)

cachedUser, exists := userMemoryCache.Get(email)
if exists {
	// if it exists, cast the type of the cachedUser and return
	return cachedUser.(*db.UserModel), nil
}

// Example of getting a collection
userCollection := EpicServerDb.GetMongoCollection(s, dbConnectionName, os.Getenv("DATABASE_NAME"), "users")

// build query for fetching user by email
result := collection.FindOne(ctx, bson.M{"email": email})

var user *db.UserModel
// decode results to variable
err := result.Decode(&user)
if err != nil {
	return nil, err
}

// add user to cache
userMemoryCache.Set(email, user, 10*time.Minute)

return user, nil
```

This allows for multiple database connections to be added to the server instance.

## Example Hello world

```go
package main

import (
	"crypto/rand"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	. "github.com/tomskip123/EpicServer"
)

func main() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}

	var routes = RouteGroup{
		Prefix: "/",
		Routes: []Route{
			Get("/", func(ctx *gin.Context, s *Server) {
				ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
			}),
		},
	}

	serverParam := &NewServerParam{
		Configs: []Option{
			SetSecretKey(key),
			SetHost("localhost", 3000),
		},
		AppLayer: []AppLayer{
			WithRoutes(routes),
		},
	}
	server := NewServer(serverParam)

	server.Start()
}

```

## Example of Minimal with auth server

```go
package main

import (
    . "github.com/tomskip123/EpicServer"
)

func main() {
    key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}

	publicPaths := &PublicPathConfig{
		Exact:  []string{"/"},
		Prefix: []string{},
	}

	var routes = RouteGroup{
		Prefix: "/",
		Routes: []Route{
			Get("/", func(ctx *gin.Context) {
				ctx.JSON(http.StatusOK, gin.H{"hello": "welcome"})
			}),
			Get("/protected", func(ctx *gin.Context) {
				session := MustGetSession(ctx)

				fmt.Println(session)
				ctx.JSON(http.StatusOK, gin.H{"protected": "true!"})
			}),
		},
	}

	authConfig := &SessionConfig{
		CookieName:     "session",
		CookieMaxAge:   1000,
		CookieSecure:   false,
		CookieHTTPOnly: true,
	}

	hooks := &Hooks{
		Auth: &AuthHooks{},
	}

    // ORDER OF PLUGIN METHODS MATTERS
	serverParam := &NewServerParam{
		Configs: []Option{
			SetSecretKey(key),
            SetHost("localhost", 3000),
		},
		AppLayer: []AppLayer{
			WithOAuth(
				[]Provider{
					Provider{
						Name:         "google",
						ClientId:     "",
						ClientSecret: "",
						Callback:     "http://localhost:3000/auth/google/callback",
					},
				},
				authConfig,
			),
			WithPublicPaths(*publicPaths),
			WithAuthMiddleware(*authConfig),
			WithAuthHooks(hooks.Auth),
			WithRoutes(routes),
		},
	}

	server := NewServer(serverParam)

	server.Start()
}

```

## Directory Structure

```
EpicServer
    └── README.md
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

Project Link: [https://github.com/tomskip123/EpicServer](https://github.com/tomskip123/EpicServer)
