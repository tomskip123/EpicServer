package helpers

import (
	"context"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cyberthy/server/services"
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
	// Add this import
)

func StartServer(r *gin.Engine, app *structs.App) {
	// Create a channel to listen for interrupt or terminate signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Start the server in a goroutine
	go func() {
		if err := r.Run(app.ServerConfig.Host); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server run error: %v", err)
		}
	}()

	// Wait for a signal to quit
	<-quit
	log.Println("Shutting down server...")

	// Create a context with a timeout to allow for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Disconnect from the database
	app.Database.HandleDbDisconnect(ctx, app.Database)

	log.Println("Server exiting")
}

func InitApp(
	googleClientId string,
	googleClientSecret string,
	googleOAuthCallback string,
	serverConfig *structs.ServerConfig,
	dbConfig *structs.DbConfig,
	logger structs.Logger,
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
		logger,
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
