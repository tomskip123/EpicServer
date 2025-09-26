package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v2"
)

type Config struct {
	AppName  string       `json:"appName" yaml:"appName"`
	Env      string       `json:"env" yaml:"env"` // "dev", "staging", "prod"
	Server   ServerConfig `json:"server" yaml:"server"`
	Logger   LoggerConfig `json:"logger" yaml:"logger"`
	Database DBConfig     `json:"database" yaml:"database"`
	Features Features     `json:"features" yaml:"features"`
	Auth     AuthConfig   `json:"auth" yaml:"auth"`
}

type ServerConfig struct {
	Host            string        `json:"host" yaml:"host"`
	Port            int           `json:"port" yaml:"port"`
	ReadTimeout     time.Duration `json:"readTimeout" yaml:"readTimeout"`         // not used yet
	WriteTimeout    time.Duration `json:"writeTimeout" yaml:"writeTimeout"`       // not used yet
	ShutdownTimeout time.Duration `json:"shutdownTimeout" yaml:"shutdownTimeout"` // not used yet
}

type LoggerConfig struct {
	IsDebug          bool   `json:"isDebug" yaml:"isDebug"`
	RequestLogFormat string `json:"requestLogFormat" yaml:"requestLogFormat"`
}

type DBConfig struct {
	Driver          string `json:"driver" yaml:"driver"`                   // "postgres","mysql","sqlite" // not used
	DSN             string `json:"dsn" yaml:"dsn"`                         // not used
	MaxOpenConns    int    `json:"maxOpenConns" yaml:"maxOpenConns"`       // not used
	MaxIdleConns    int    `json:"maxIdleConns" yaml:"maxIdleConns"`       // not used
	ConnMaxLifetime string `json:"connMaxLifetime" yaml:"connMaxLifetime"` // e.g. "30m" // not used
}

type Features struct {
	EnableMetrics bool `json:"enableMetrics" yaml:"enableMetrics"` // not used
	EnablePprof   bool `json:"enablePprof" yaml:"enablePprof"`     // not used
	EnableAuth    bool `json:"enableAuth" yaml:"enableAuth"`       // not used
	EnableDB      bool `json:"enableDB" yaml:"enableDB"`
}

type OAuth2Provider struct {
	ClientID     string `json:"clientId" yaml:"clientId"`
	ClientSecret string `json:"clientSecret" yaml:"clientSecret"`
	// Either set a well-known provider name (github, gitlab, google, microsoft)
	// or specify explicit auth/token URLs below.
	Provider    string   `json:"provider" yaml:"provider"`
	AuthURL     string   `json:"authUrl" yaml:"authUrl"`
	TokenURL    string   `json:"tokenUrl" yaml:"tokenUrl"`
	RedirectURL string   `json:"redirectUrl" yaml:"redirectUrl"`
	Scopes      []string `json:"scopes" yaml:"scopes"`
}

type AuthConfig struct {
	OAuth2Providers map[string]OAuth2Provider `json:"oauth2Providers" yaml:"oauth2Providers"`
	DefaultProvider string                    `json:"defaultProvider" yaml:"defaultProvider"`
}

func Default() Config {
	return Config{
		AppName: "epicserver",
		Env:     "dev",
		Server: ServerConfig{
			Host:            "0.0.0.0",
			Port:            8080,
			ReadTimeout:     10 * time.Second,
			WriteTimeout:    10 * time.Second,
			ShutdownTimeout: 10 * time.Second,
		},
		Logger: LoggerConfig{
			IsDebug:          false,
			RequestLogFormat: "off",
		},
		Database: DBConfig{
			Driver:          "sqlite",
			DSN:             "file:epic.db?_busy_timeout=5000",
			MaxOpenConns:    10,
			MaxIdleConns:    5,
			ConnMaxLifetime: "30m",
		},
		Features: Features{
			EnableMetrics: true,
			EnablePprof:   false,
			EnableDB:      false,
		},
		Auth: AuthConfig{
			OAuth2Providers: map[string]OAuth2Provider{},
			DefaultProvider: "",
		},
	}
}

func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be 1..65535")
	}

	if c.Database.Driver == "" || c.Database.DSN == "" {
		return errors.New("database.driver and database.dsn are required")
	}
	return nil
}

func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config: %w", err)
		}
		switch ext := filepath.Ext(path); ext {
		case ".json":
			if err := json.Unmarshal(b, &cfg); err != nil {
				return cfg, fmt.Errorf("parse json: %w", err)
			}
		case ".yaml", ".yml":
			var y struct{}
			_ = y // avoid import cycles in snippet
			if err := yaml.Unmarshal(b, &cfg); err != nil {
				return cfg, fmt.Errorf("parse yaml: %w", err)
			}
			return cfg, nil
		default:
			return cfg, fmt.Errorf("unsupported config extension: %s", ext)
		}
	}

	applyEnvOverrides(&cfg)

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func Getenv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func applyEnvOverrides(c *Config) {
	// Examples (add whatever you need):
	if v := os.Getenv("APP_NAME"); v != "" {
		c.AppName = v
	}
	if v := os.Getenv("APP_ENV"); v != "" {
		c.Env = v
	}
	if v := os.Getenv("SERVER_HOST"); v != "" {
		c.Server.Host = v
	}
	if v := os.Getenv("SERVER_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			c.Server.Port = p
		}
	}

	// Logger overrides
	if v := os.Getenv("LOGGER_IS_DEBUG"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Logger.IsDebug = b
		}
	}
	if v := os.Getenv("LOGGER_REQUEST_LOG_FORMAT"); v != "" {
		c.Logger.RequestLogFormat = v
	}

	// DB overrides
	if v := os.Getenv("DB_DRIVER"); v != "" {
		c.Database.Driver = v
	}
	if v := os.Getenv("DB_DSN"); v != "" {
		c.Database.DSN = v
	}
	if v := os.Getenv("DB_MAX_OPEN_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Database.MaxOpenConns = n
		}
	}
	if v := os.Getenv("DB_MAX_IDLE_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Database.MaxIdleConns = n
		}
	}
	if v := os.Getenv("DB_CONN_MAX_LIFETIME"); v != "" {
		c.Database.ConnMaxLifetime = v
	}

}
