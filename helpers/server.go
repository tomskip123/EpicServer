package helpers

import (
	"context"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/cyberthy/server/services"
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
	// Add this import
)

func StartServer(r *gin.Engine, app *structs.App) {
	defer app.Database.HandleDbDisconnect(context.Background(), app.Database)

	r.Run(app.ServerConfig.Host)

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	log.Println("Shutting down server...")
	log.Println("Server exiting")
}

func InitApp(
	googleClientId string,
	googleClientSecret string,
	googleOAuthCallback string,
	serverConfig *structs.ServerConfig,
	dbConfig *structs.DbConfig,
) (*gin.Engine, *structs.App) {
	r := gin.New()
	r.UseH2C = true

	ctx := context.Background()
	r.SetTrustedProxies(nil)
	database := &structs.DB{}

	if dbConfig != nil {
		SetupDatabase(ctx, database, dbConfig)
	}

	authConfig := services.NewAuthConfig(
		ctx,
		googleClientId,
		googleClientSecret,
		"nts",
		googleOAuthCallback,
	)

	app := structs.NewApp(
		authConfig,
		database,
		serverConfig,
		serverConfig.SecureCookie,
		serverConfig.CookieDomain,
		serverConfig.CSPHeader,
		serverConfig.NotificationHost,
	)

	r.SetFuncMap(structs.TemplateFuncMap)

	var paths []string
	if serverConfig.TemplatesDir != "" {
		paths = append(paths, BuildFileList(serverConfig.TemplatesDir)...)
	}

	if serverConfig.PackageTemplatesDir != "" {
		paths = append(paths, BuildFileList(serverConfig.PackageTemplatesDir)...)
	}

	if len(paths) > 0 {
		r.LoadHTMLFiles(paths...)
	}

	return r, app
}

func BuildFileList(root string) []string {
	var paths []string
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if strings.Contains(path, ".html") {
			paths = append(paths, path)
		}
		return nil
	})

	return paths
}
