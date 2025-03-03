package EpicServerDb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tomskip123/EpicServer/v2"
)

// Variable to allow mocking in tests
var gormDBFunc = GetGormDB

// TestAutoMigrateModels tests the AutoMigrateModels function
func TestAutoMigrateModels(t *testing.T) {
	// Create a server
	s := &EpicServer.Server{
		Db: make(map[string]interface{}),
	}

	// Set up mocking for GetGormDB
	// Rather than mocking the function, we'll mock the database in the server

	// Set up test models
	type TestModel1 struct {
		ID   uint
		Name string
	}

	type TestModel2 struct {
		ID    uint
		Email string
	}

	// Test case: DB not found
	// This should trigger the GetGormDB panic path
	assert.Panics(t, func() {
		_ = AutoMigrateModels(s, "nonexistent", &TestModel1{}, &TestModel2{})
	}, "Should panic when DB not found")
}

// TestWithGorm tests the WithGorm function with SQLite in-memory database
// which doesn't require external database connections
func TestWithGorm(t *testing.T) {
	tests := []struct {
		name       string
		gormConfig *GormConfig
		wantError  bool
	}{
		{
			name: "sqlite in-memory connection",
			gormConfig: &GormConfig{
				ConnectionName: "test_sqlite",
				Dialect:        "sqlite",
				DSN:            ":memory:",
			},
			wantError: false,
		},
		{
			name: "invalid dialect",
			gormConfig: &GormConfig{
				ConnectionName: "test_invalid",
				Dialect:        "invalid",
				DSN:            ":memory:",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock logger that implements the Logger interface
			mockLogger := &testLogger{}

			s := &EpicServer.Server{
				Db:     make(map[string]interface{}),
				Logger: mockLogger,
			}

			// Create the app layer
			appLayer := WithGorm(tt.gormConfig)

			// Apply the layer - should not panic
			assert.NotPanics(t, func() {
				appLayer(s)
			})

			if tt.wantError {
				// For invalid dialect, the connection should not be in the map
				_, ok := s.Db[tt.gormConfig.ConnectionName].(*GormConfig)
				assert.False(t, ok, "Should not have stored a valid connection for invalid dialect")
				return
			}

			// Verify the connection was stored
			assert.Contains(t, s.Db, tt.gormConfig.ConnectionName)

			// Test the getter
			db := GetGormDB(s, tt.gormConfig.ConnectionName)
			assert.NotNil(t, db)
		})
	}
}

// TestWithMySQLMock tests the WithMySQL function with a mock approach
func TestWithMySQLMock(t *testing.T) {
	config := MySQLConfig{
		ConnectionName: "test_mysql",
		Host:           "localhost",
		Port:           3306,
		User:           "test",
		Password:       "test",
		Database:       "test",
	}

	// Create a mock server with a logger
	s := &EpicServer.Server{
		Db:     make(map[string]interface{}),
		Logger: &testLogger{},
	}

	// This just tests that the function can be called without error
	mysqlLayer := WithMySQL(config)
	assert.NotNil(t, mysqlLayer)

	// Should not panic
	assert.NotPanics(t, func() {
		mysqlLayer(s)
	})
}

// TestWithPostgresMock tests the WithPostgres function with a mock approach
func TestWithPostgresMock(t *testing.T) {
	config := PostgresConfig{
		ConnectionName: "test_postgres",
		Host:           "localhost",
		Port:           5432,
		User:           "test",
		Password:       "test",
		Database:       "test",
		SSLMode:        "disable",
	}

	// Create a mock server with a logger
	s := &EpicServer.Server{
		Db:     make(map[string]interface{}),
		Logger: &testLogger{},
	}

	// This just tests that the function can be called without error
	postgresLayer := WithPostgres(config)
	assert.NotNil(t, postgresLayer)

	// Should not panic
	assert.NotPanics(t, func() {
		postgresLayer(s)
	})
}

// TestWithMongoMock tests the WithMongo function with a mock approach
func TestWithMongoMock(t *testing.T) {
	config := &MongoConfig{
		ConnectionName: "test_mongo",
		URI:            "mongodb://localhost:27017",
		DatabaseName:   "test",
	}

	// Create a mock server with a logger
	s := &EpicServer.Server{
		Db:     make(map[string]interface{}),
		Logger: &testLogger{},
	}

	// This just tests that the function can be called without error
	mongoLayer := WithMongo(config)
	assert.NotNil(t, mongoLayer)

	// Should not panic
	assert.NotPanics(t, func() {
		mongoLayer(s)
	})
}

func TestGetGormDB(t *testing.T) {
	// Create a mock server with a logger
	s := &EpicServer.Server{
		Db:     make(map[string]interface{}),
		Logger: &testLogger{},
	}

	// Setup a valid GORM config
	gormConfig := &GormConfig{
		ConnectionName: "test_get",
		Dialect:        "sqlite",
		DSN:            ":memory:",
	}

	// Skip actual connection in this test
	s.Db[gormConfig.ConnectionName] = gormConfig

	t.Run("panic on invalid connection name", func(t *testing.T) {
		assert.Panics(t, func() {
			GetGormDB(s, "nonexistent")
		})
	})

	t.Run("panic on incompatible type", func(t *testing.T) {
		s.Db["wrong_type"] = "not a gorm config"
		assert.Panics(t, func() {
			GetGormDB(s, "wrong_type")
		})
	})
}
