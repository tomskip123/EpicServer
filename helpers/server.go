package helpers

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/cyberthy/server/services"
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
)

func StartServer(r *gin.Engine, app *structs.App) {
	defer app.Database.HandleDbDisconnect(context.Background(), app.Database)

	// if os.Getenv("ENVIRONMENT") == "production" {
	// 	server, m := BuildTLS(r, app)

	// 	// Redirect HTTP to HTTPS
	// 	go func() {
	// 		if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil && err != http.ErrServerClosed {
	// 			log.Fatalf("HTTP redirect server failed: %s\n", err)
	// 		}
	// 	}()

	// 	// Start the HTTPS server in a goroutine
	// 	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
	// 		log.Fatalf("Failed to start HTTPS server: %s\n", err)
	// 	}
	// } else {

	// }

	// Start the HTTP server in a goroutine
	if err := r.Run(app.ServerConfig.Host); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Failed to start HTTP server: %s\n", err)
	}

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	log.Println("Shutting down server...")

	// The context is used to inform the server it has 5 seconds to finish the request it is currently handling
	// ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// defer cancel()
	//
	// if os.Getenv("ENVIRONMENT") == "production" {
	// 	server, _ := BuildTLS(r, app)
	// 	if err := server.Shutdown(ctx); err != nil {
	// 		log.Fatal("Server forced to shutdown:", err)
	// 	}
	// }
	log.Println("Server exiting")
}

func InitApp(
	googleClientId string,
	googleClientSecret string,
	googleOAuthCallback string,
	serverConfig *structs.ServerConfig,
	dbConfig *structs.DbConfig,
) (*gin.Engine, *structs.App) {
	r := gin.Default()
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
	paths = append(paths, BuildFileList(serverConfig.TemplatesDir)...)
	paths = append(paths, BuildFileList(serverConfig.PackageTemplatesDir)...)

	r.LoadHTMLFiles(paths...)

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
