package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
}

type ServerConfig struct {
	Host            string        `json:"host" yaml:"host"`
	Port            int           `json:"port" yaml:"port"`
	ReadTimeout     time.Duration `json:"readTimeout" yaml:"readTimeout"`
	WriteTimeout    time.Duration `json:"writeTimeout" yaml:"writeTimeout"`
	ShutdownTimeout time.Duration `json:"shutdownTimeout" yaml:"shutdownTimeout"`
}

type LoggerConfig struct {
	Level      string `json:"level" yaml:"level"` // "debug","info","warn","error"
	JSON       bool   `json:"json" yaml:"json"`
	WithCaller bool   `json:"withCaller" yaml:"withCaller"`
}

type DBConfig struct {
	Driver          string `json:"driver" yaml:"driver"` // "postgres","mysql","sqlite"
	DSN             string `json:"dsn" yaml:"dsn"`
	MaxOpenConns    int    `json:"maxOpenConns" yaml:"maxOpenConns"`
	MaxIdleConns    int    `json:"maxIdleConns" yaml:"maxIdleConns"`
	ConnMaxLifetime string `json:"connMaxLifetime" yaml:"connMaxLifetime"` // e.g. "30m"
}

type Features struct {
	EnableMetrics bool `json:"enableMetrics" yaml:"enableMetrics"`
	EnablePprof   bool `json:"enablePprof" yaml:"enablePprof"`
	EnableAuth    bool `json:"enableAuth" yaml:"enableAuth"`
}

type OAuth2Provider struct {
	ClientID     string `json:"clientId" yaml:"clientId"`
	ClientSecret string `json:"clientSecret" yaml:"clientSecret"`
}

type AuthConfig struct {
	OAuth2Providers map[string]OAuth2Provider `json:"oauth2Providers" yaml:"oauth2Providers"`
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
			Level:      "info",
			JSON:       false,
			WithCaller: true,
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
		},
	}
}

func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be 1..65535")
	}
	switch strings.ToLower(c.Logger.Level) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logger.level must be one of debug|info|warn|error")
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
	if v := os.Getenv("LOGGER_LEVEL"); v != "" {
		c.Logger.Level = strings.ToLower(v)
	}
	if v := os.Getenv("LOGGER_JSON"); v != "" {
		c.Logger.JSON = v == "1" || strings.EqualFold(v, "true")
	}
	if v := os.Getenv("LOGGER_WITH_CALLER"); v != "" {
		c.Logger.WithCaller = v == "1" || strings.EqualFold(v, "true")
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
