package structs

import (
	"encoding/json"
	"os"

	"github.com/gin-gonic/gin"
)

// Logger interface defines the logging behavior
type Logger interface {
	Debug(args ...interface{})
	Info(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
}

type App struct {
	Auth         *Auth
	Database     *DB
	Assets       *Assets
	Config       *AppConfig
	ServerConfig *ServerConfig
	Logger       Logger
}

type AppConfig struct {
	Host             string
	CookieSecure     bool
	CookieDomain     string
	Origins          []string
	CSP              string
	NotificationHost string
}

type PageScript struct {
	Src string
}

type PageCss struct {
	Href string
}

type AssetName = string
type Assets = map[AssetName]*ManifestObject

type InitFunc func(r *gin.Engine, app *App)

func NewApp(
	authConfig *Auth,
	db *DB,
	serverConfig *ServerConfig,
	cookieSecure bool,
	cookieDomain string,
	csp string,
	notificationHost string,
	logger Logger,
) *App {
	// also setup the db stuff

	return &App{
		Auth:     authConfig,
		Database: db,
		Assets:   &Assets{},
		Config: &AppConfig{
			Host:             serverConfig.Host,
			CookieSecure:     cookieSecure,
			CookieDomain:     cookieDomain,
			Origins:          serverConfig.Origins,
			CSP:              csp,
			NotificationHost: notificationHost,
		},
		ServerConfig: serverConfig,
		Logger:       logger,
	}
}

type ManifestObject struct {
	File    string   `json:"file"`
	Name    string   `json:"name"`
	Src     string   `json:"src"`
	IsEntry bool     `json:"isEntry"`
	CSS     []string `json:"css"`
	Assets  []string `json:"assets"`
	Imports []string `json:"imports"`
}

type Manifest = map[string]ManifestObject

func BuildAssets(filePath string) *Assets {
	file, _ := os.Open(filePath)
	defer file.Close()

	// Create an instance of the struct to hold the data
	var manifest Manifest

	// Create a new JSON decoder and decode the file into the struct
	decoder := json.NewDecoder(file)
	decoder.Decode(&manifest)
	var assets = &Assets{}

	for key, manAsset := range manifest {
		(*assets)[key] = &manAsset
	}

	return assets
}
