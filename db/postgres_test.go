package EpicServerDb

import (
	"database/sql"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tomskip123/EpicServer"
)

func TestWithPostgres(t *testing.T) {
	// Skip if we're not running in a CI environment with proper DB access
	if os.Getenv("CI_TEST_DB") != "true" {
		t.Skip("Skipping database tests in non-CI environment")
	}

	tests := []struct {
		name           string
		postgresConfig PostgresConfig
		wantPanic      bool
	}{
		{
			name: "invalid connection string",
			postgresConfig: PostgresConfig{
				ConnectionName: "test_invalid",
				Host:           "nonexistent-host",
				Port:           5432,
				User:           "user",
				Password:       "password",
				Database:       "nonexistent",
				SSLMode:        "disable",
			},
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &EpicServer.Server{
				Db: make(map[string]interface{}),
			}

			appLayer := WithPostgres(tt.postgresConfig)

			if tt.wantPanic {
				assert.Panics(t, func() {
					appLayer(s)
				})
				return
			}

			// Should not panic
			assert.NotPanics(t, func() {
				appLayer(s)
			})

			// Verify the connection was stored
			assert.Contains(t, s.Db, tt.postgresConfig.ConnectionName)
		})
	}
}

func TestGetPostgresDB(t *testing.T) {
	s := &EpicServer.Server{
		Db: make(map[string]interface{}),
	}

	// Create a mock connection name
	connectionName := "test_get"

	// Store a mock DB
	db := &sql.DB{}
	s.Db[connectionName] = db

	t.Run("valid connection", func(t *testing.T) {
		result := GetPostgresDB(s, connectionName)
		assert.Equal(t, db, result)
	})

	t.Run("panic on invalid connection name", func(t *testing.T) {
		assert.Panics(t, func() {
			GetPostgresDB(s, "nonexistent")
		})
	})

	t.Run("panic on incompatible type", func(t *testing.T) {
		s.Db["wrong_type"] = "not a sql.DB"
		assert.Panics(t, func() {
			GetPostgresDB(s, "wrong_type")
		})
	})
}
