package EpicServer

import (
	"os"
	"reflect"
	"testing"
)

func TestConfigOptions(t *testing.T) {
	tests := []struct {
		name     string
		option   Option
		want     *Config
		validate func(*testing.T, *Config)
	}{
		{
			name:   "set host and port",
			option: SetHost("127.0.0.1", 8080),
			validate: func(t *testing.T, c *Config) {
				if c.Server.Host != "127.0.0.1" || c.Server.Port != 8080 {
					t.Errorf("host/port = %s:%d, want 127.0.0.1:8080", c.Server.Host, c.Server.Port)
				}
			},
		},
		{
			name:   "set secret key",
			option: SetSecretKey([]byte("test-secret")),
			validate: func(t *testing.T, c *Config) {
				if !reflect.DeepEqual(c.SecretKey, []byte("test-secret")) {
					t.Error("secret key not set correctly")
				}
			},
		},
		{
			name:   "set custom config",
			option: SetCustomConfig(map[string]interface{}{"test": true}),
			validate: func(t *testing.T, c *Config) {
				custom := c.Custom.(map[string]interface{})
				if v, ok := custom["test"]; !ok || v != true {
					t.Error("custom config not set correctly")
				}
			},
		},
		{
			name:   "set environment",
			option: SetEnvironment("production"),
			validate: func(t *testing.T, c *Config) {
				if c.Server.Environment != "production" {
					t.Errorf("environment = %s, want production", c.Server.Environment)
				}
			},
		},
		{
			name:   "set secure cookie",
			option: SetSecureCookie(true),
			validate: func(t *testing.T, c *Config) {
				if c.Security.SecureCookie != true {
					t.Errorf("secure cookie = %v, want true", c.Security.SecureCookie)
				}
			},
		},
		{
			name:   "set cookie domain",
			option: SetCookieDomain("example.com"),
			validate: func(t *testing.T, c *Config) {
				if c.Security.CookieDomain != "example.com" {
					t.Errorf("cookie domain = %s, want example.com", c.Security.CookieDomain)
				}
			},
		},
		{
			name:   "set CSP header",
			option: SetCSPHeader("default-src 'self'"),
			validate: func(t *testing.T, c *Config) {
				if c.Security.CSPHeader != "default-src 'self'" {
					t.Errorf("CSP header = %s, want default-src 'self'", c.Security.CSPHeader)
				}
			},
		},
		{
			name:   "set CORS origins",
			option: SetCORSOrigins([]string{"https://example.com", "https://api.example.com"}),
			validate: func(t *testing.T, c *Config) {
				if len(c.Security.Origins) != 2 {
					t.Errorf("CORS origins length = %d, want 2", len(c.Security.Origins))
				}
				if c.Security.Origins[0] != "https://example.com" {
					t.Errorf("CORS origin 0 = %s, want https://example.com", c.Security.Origins[0])
				}
				if c.Security.Origins[1] != "https://api.example.com" {
					t.Errorf("CORS origin 1 = %s, want https://api.example.com", c.Security.Origins[1])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{}
			tt.option(config)
			tt.validate(t, config)
		})
	}
}

func TestGetCustomConfig(t *testing.T) {
	customData := map[string]string{"key": "value"}
	s := &Server{
		Config: &Config{
			Custom: customData,
		},
	}

	got := GetCustomConfig(s)
	if !reflect.DeepEqual(got, customData) {
		t.Errorf("GetCustomConfig() = %v, want %v", got, customData)
	}
}

func TestConfigValidationError(t *testing.T) {
	err := &ConfigValidationError{
		Field:   "SecretKey",
		Message: "secret key is required",
	}

	errMsg := err.Error()
	expected := "configuration error for SecretKey: secret key is required"
	if errMsg != expected {
		t.Errorf("Error() = %v, want %v", errMsg, expected)
	}
}

func TestWithEnvVars(t *testing.T) {
	// Save current environment and restore after test
	envVars := []struct {
		key   string
		value string
	}{
		{"EPICSERVER_SERVER_HOST", "env-test-host"},
		{"EPICSERVER_SERVER_PORT", "8888"},
		{"EPICSERVER_SERVER_ENVIRONMENT", "testing"},
	}

	// Save original values
	origEnv := make(map[string]string)
	for _, env := range envVars {
		origEnv[env.key] = os.Getenv(env.key)
	}

	// Set test values
	for _, env := range envVars {
		os.Setenv(env.key, env.value)
	}

	// Run test
	config := &Config{}
	WithEnvVars()(config)

	// Verify values
	if config.Server.Host != "env-test-host" {
		t.Errorf("env host = %s, want env-test-host", config.Server.Host)
	}
	if config.Server.Port != 8888 {
		t.Errorf("env port = %d, want 8888", config.Server.Port)
	}
	if config.Server.Environment != "testing" {
		t.Errorf("env environment = %s, want testing", config.Server.Environment)
	}

	// Restore original environment
	for _, env := range envVars {
		if origEnv[env.key] != "" {
			os.Setenv(env.key, origEnv[env.key])
		} else {
			os.Unsetenv(env.key)
		}
	}
}
