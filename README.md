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

## Example of standard server

```go
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
						ClientId:     "1023893548171-5uolqrah0ive18gigggubd8h9pl3hrto.apps.googleusercontent.com",
						ClientSecret: "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",
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
