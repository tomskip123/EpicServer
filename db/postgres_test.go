package EpicServerDb

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tomskip123/EpicServer/v2"
)

// TestGetPostgresDB tests the GetPostgresDB function
func TestGetPostgresDB(t *testing.T) {
	// Create a server
	s := &EpicServer.Server{
		Db: make(map[string]interface{}),
	}

	// Add a mock DB
	mockDB := &sql.DB{}
	s.Db["test-postgres"] = mockDB

	// Test retrieving the DB
	db := GetPostgresDB(s, "test-postgres")
	assert.Equal(t, mockDB, db, "Should return the correct DB")

	// Test with non-existent DB
	assert.Panics(t, func() {
		GetPostgresDB(s, "non-existent")
	}, "Should panic for non-existent DB")

	// Test with wrong type
	s.Db["wrong-type"] = "not a DB"
	assert.Panics(t, func() {
		GetPostgresDB(s, "wrong-type")
	}, "Should panic for wrong type")
}

func TestWithPostgresErrorCases(t *testing.T) {
	// Save the original functions
	originalOpen := sqlOpen
	originalPing := sqlPing

	// Restore them after the test
	defer func() {
		sqlOpen = originalOpen
		sqlPing = originalPing
	}()

	// Create a mock server
	s := &EpicServer.Server{
		Db:     make(map[string]interface{}),
		Logger: &testLogger{},
	}

	// Test case 1: SQL Open error
	sqlOpen = func(driverName, dataSourceName string) (*sql.DB, error) {
		return nil, sql.ErrConnDone
	}

	sqlPing = func(db *sql.DB) error {
		return nil // This should not be called
	}

	// Create the config
	config := PostgresConfig{
		ConnectionName: "test-postgres-error",
		Host:           "localhost",
		Port:           5432,
		User:           "user",
		Password:       "password",
		Database:       "testdb",
		SSLMode:        "disable",
	}

	// Create and apply the app layer
	appLayer := WithPostgres(config)

	// This should not panic but add an error to the server
	assert.NotPanics(t, func() {
		appLayer(s)
	})

	// Verify the connection was not added to the server
	_, ok := s.Db[config.ConnectionName].(*sql.DB)
	assert.False(t, ok, "Should not have added a database connection")

	// Test case 2: Ping error
	mockDB := &sql.DB{}
	sqlOpen = func(driverName, dataSourceName string) (*sql.DB, error) {
		return mockDB, nil
	}

	sqlPing = func(db *sql.DB) error {
		return sql.ErrConnDone
	}

	// This should not panic but add an error to the server
	assert.NotPanics(t, func() {
		appLayer(s)
	})

	// Verify the connection was not added to the server
	_, ok = s.Db[config.ConnectionName].(*sql.DB)
	assert.False(t, ok, "Should not have added a database connection")
}
