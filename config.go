package EpicServer

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config represents the server configuration
type Config struct {
	Server struct {
		Host        string
		Port        int
		Environment string
	}
	Security struct {
		SecureCookie bool
		CookieDomain string
		CSPHeader    string
		Origins      []string
	}
	SecretKey []byte
	Custom    interface{}
}

// Option is a function that modifies the configuration
type Option func(*Config)

// ConfigValidationError represents an error in configuration validation
type ConfigValidationError struct {
	Field   string
	Message string
}

func (e *ConfigValidationError) Error() string {
	return fmt.Sprintf("configuration error for %s: %s", e.Field, e.Message)
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if len(c.SecretKey) == 0 {
		return &ConfigValidationError{
			Field:   "SecretKey",
			Message: "secret key is required",
		}
	}

	if c.Server.Port < 0 || c.Server.Port > 65535 {
		return &ConfigValidationError{
			Field:   "Server.Port",
			Message: fmt.Sprintf("invalid port number: %d", c.Server.Port),
		}
	}

	return nil
}

// SetHost sets the host and port
func SetHost(host string, port int) Option {
	return func(c *Config) {
		c.Server.Host = host
		c.Server.Port = port
	}
}

// SetSecretKey sets the secret key
func SetSecretKey(secretKey []byte) Option {
	return func(c *Config) {
		c.SecretKey = secretKey
	}
}

// SetEnvironment sets the server environment (development, production, etc.)
func SetEnvironment(env string) Option {
	return func(c *Config) {
		c.Server.Environment = env
	}
}

// SetSecureCookie sets whether cookies should be secure
func SetSecureCookie(secure bool) Option {
	return func(c *Config) {
		c.Security.SecureCookie = secure
	}
}

// SetCookieDomain sets the cookie domain
func SetCookieDomain(domain string) Option {
	return func(c *Config) {
		c.Security.CookieDomain = domain
	}
}

// SetCSPHeader sets the Content-Security-Policy header
func SetCSPHeader(csp string) Option {
	return func(c *Config) {
		c.Security.CSPHeader = csp
	}
}

// SetCORSOrigins sets the allowed CORS origins
func SetCORSOrigins(origins []string) Option {
	return func(c *Config) {
		c.Security.Origins = origins
	}
}

// SetCustomConfig sets a custom configuration
func SetCustomConfig(customConfig interface{}) Option {
	return func(c *Config) {
		c.Custom = customConfig
	}
}

// GetCustomConfig gets the custom configuration from the server
func GetCustomConfig(s *Server) interface{} {
	return s.Config.Custom
}

// WithEnvVars loads configuration from environment variables
// Environment variables are expected to be in the format EPICSERVER_SECTION_KEY
// For example, EPICSERVER_SERVER_PORT would set Config.Server.Port
func WithEnvVars() Option {
	return func(c *Config) {
		// Check for host and port
		if host := os.Getenv("EPICSERVER_SERVER_HOST"); host != "" {
			c.Server.Host = host
		}

		if portStr := os.Getenv("EPICSERVER_SERVER_PORT"); portStr != "" {
			if port, err := strconv.Atoi(portStr); err == nil {
				c.Server.Port = port
			}
		}

		// Check for environment
		if env := os.Getenv("EPICSERVER_SERVER_ENVIRONMENT"); env != "" {
			c.Server.Environment = env
		}

		// Check for security settings
		if secureCookieStr := os.Getenv("EPICSERVER_SECURITY_SECURECOOKIE"); secureCookieStr != "" {
			c.Security.SecureCookie = strings.ToLower(secureCookieStr) == "true"
		}

		if cookieDomain := os.Getenv("EPICSERVER_SECURITY_COOKIEDOMAIN"); cookieDomain != "" {
			c.Security.CookieDomain = cookieDomain
		}

		if cspHeader := os.Getenv("EPICSERVER_SECURITY_CSPHEADER"); cspHeader != "" {
			c.Security.CSPHeader = cspHeader
		}

		if origins := os.Getenv("EPICSERVER_SECURITY_ORIGINS"); origins != "" {
			c.Security.Origins = strings.Split(origins, ",")
		}

		// Check for secret key
		if secretKey := os.Getenv("EPICSERVER_SECRETKEY"); secretKey != "" {
			c.SecretKey = []byte(secretKey)
		}
	}
}
