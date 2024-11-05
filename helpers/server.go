package helpers

import (
	"context"
	"crypto/tls"
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
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme/autocert"
)

func StartServer(r *gin.Engine, app *structs.App) {
	defer app.Database.HandleDbDisconnect(context.Background(), app.Database)

	// Setup autocert manager
	m := &autocert.Manager{
		Cache:      autocert.DirCache("certs"), // Folder for storing certificates
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(app.ServerConfig.Host), // Your domain here
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		GetCertificate: m.GetCertificate,
		NextProtos:     []string{http3.NextProtoH3},
	}

	server := &http3.Server{
		Addr:      app.ServerConfig.Host,
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("Failed to start HTTP/3 server: %v", err)
		}
	}()

	// Start HTTP server for autocert
	go func() {
		httpServer := &http.Server{
			Addr:    ":http",
			Handler: m.HTTPHandler(nil),
		}
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	log.Println("Shutting down server...")
	server.Close()
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
