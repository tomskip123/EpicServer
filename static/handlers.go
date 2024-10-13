package static

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Path struct {
	Route     string
	Path      string
	Directory bool
}

type Config struct {
	Paths []Path
}

func RegisterStaticRoutes(r *gin.Engine, config *Config) {
	for _, path := range config.Paths {
		if path.Directory {
			r.StaticFS(path.Route, http.Dir(path.Path))
		} else {
			r.StaticFile(path.Route, path.Path)
		}
	}
}
