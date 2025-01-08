package EpicServer

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// This Static Directory
func WithStaticDirectory(path string, embededFS *embed.FS, fileSystemPath string) AppLayer {
	return func(s *Server) {
		assets, err := fs.Sub(embededFS, fileSystemPath)
		if err != nil {
			panic(err)
		}

		s.engine.StaticFS(path, http.FS(assets))
	}
}

func WithStaticFile(path string, embededFS *embed.FS, filesystemPath string, mimetype string) AppLayer {
	return func(s *Server) {
		ServeEmbededFile(s, embededFS, path, filesystemPath, mimetype)
	}
}

func WithSPACatchAll(
	embededFs *embed.FS,
	filesystemPath string,
	spaEntryPointPath string,
) AppLayer {
	return func(s *Server) {
		s.engine.NoRoute(func(c *gin.Context) {
			// if !strings.HasPrefix(c.Request.RequestURI, "/api") && !strings.HasPrefix(c.Request.RequestURI, "/auth") {
			var fileToReturn fs.File

			// here we ensure that every
			assetFile, assetErr := embededFs.Open(filesystemPath + c.Request.RequestURI)

			if assetErr == nil {
				fileToReturn = assetFile
				defer assetFile.Close()
			}

			if assetFile == nil {
				file, err := embededFs.Open(spaEntryPointPath)
				if err != nil {
					fmt.Println("Error opening index.html:", err)
					c.String(http.StatusInternalServerError, "Internal Server Error")
					return
				}

				fileToReturn = file
				defer file.Close()
			}

			content, err := io.ReadAll(fileToReturn)
			if err != nil {
				fmt.Println("Error reading index.html:", err)
				c.String(http.StatusInternalServerError, "Internal Server Error")
				return
			}

			// Detect the content type
			contentType := http.DetectContentType(content)

			if strings.Contains(c.Request.RequestURI, ".webmanifest") {
				contentType = "application/manifest+json; charset=utf-8"
			}

			if strings.Contains(c.Request.RequestURI, ".js") {
				contentType = "text/javascript; charset=utf-8"
			}

			c.Data(http.StatusOK, contentType, content)
			// } else {
			// 	fmt.Println("UNCAUGHT ENDPOINT")
			// }
			//default 404 page not found
		})
	}

}

func ServeEmbededFile(server *Server, embededFS *embed.FS, path string, file string, defaultContentType string) {
	// Serve a single file from the embedded file system
	server.engine.GET(fmt.Sprintf("/%v", path), func(c *gin.Context) {
		file, err := embededFS.Open(fmt.Sprintf("%v", file))
		if err != nil {
			fmt.Println("Error opening file:", err)
			c.String(http.StatusInternalServerError, "Internal Server Error")
			return
		}
		defer file.Close()

		content, err := io.ReadAll(file)
		if err != nil {
			fmt.Println("Error reading file:", err)
			c.String(http.StatusInternalServerError, "Internal Server Error")
			return
		}

		// Detect the content type
		contentType := http.DetectContentType(content)
		if contentType == "application/octet-stream" {
			contentType = defaultContentType
		}

		c.Data(http.StatusOK, contentType+"; charset=utf-8", content)
	})
}
