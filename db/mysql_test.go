package EpicServerDb

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tomskip123/EpicServer/v2"
)

// TestGetMySQLDB tests the GetMySQLDB function
func TestGetMySQLDB(t *testing.T) {
	// Create a server
	s := &EpicServer.Server{
		Db: make(map[string]interface{}),
	}

	// Add a mock DB
	mockDB := &sql.DB{}
	s.Db["test-mysql"] = mockDB

	// Test retrieving the DB
	db := GetMySQLDB(s, "test-mysql")
	assert.Equal(t, mockDB, db, "Should return the correct DB")

	// Test with non-existent DB
	assert.Panics(t, func() {
		GetMySQLDB(s, "non-existent")
	}, "Should panic for non-existent DB")

	// Test with wrong type
	s.Db["wrong-type"] = "not a DB"
	assert.Panics(t, func() {
		GetMySQLDB(s, "wrong-type")
	}, "Should panic for wrong type")
}

func TestWithMySQLErrorCases(t *testing.T) {
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
	config := MySQLConfig{
		ConnectionName: "test-mysql-error",
		Host:           "localhost",
		Port:           3306,
		User:           "user",
		Password:       "password",
		Database:       "testdb",
	}

	// Create and apply the app layer
	appLayer := WithMySQL(config)

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

// Mock functions to replace sql.Open and db.Ping
var sqlOpen = sql.Open
var sqlPing = func(db *sql.DB) error {
	return db.Ping()
}
