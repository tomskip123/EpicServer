package EpicServer

import (
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
