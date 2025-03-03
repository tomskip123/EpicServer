package EpicServerDb

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tomskip123/EpicServer"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TestServer is a simplified version of EpicServer.Server for testing
type TestServer struct {
	Databases map[string]interface{}
	Logger    EpicServer.Logger
}

// GetDatabase retrieves a database by name
func (s *TestServer) GetDatabase(name string) (interface{}, bool) {
	db, ok := s.Databases[name]
	return db, ok
}

// AddDatabase adds a database to the server
func (s *TestServer) AddDatabase(name string, db interface{}) {
	s.Databases[name] = db
}

// GetLogger returns the server's logger
func (s *TestServer) GetLogger() EpicServer.Logger {
	return s.Logger
}

// Helper function to get a MongoDB client for testing
func getMongoClientForTest(s *TestServer, name string) (*mongo.Client, bool) {
	db, ok := s.GetDatabase(name)
	if !ok {
		return nil, false
	}
	client, ok := db.(*mongo.Client)
	return client, ok
}

// Helper function to get a MongoDB collection for testing
func getMongoCollectionForTest(s *TestServer, connName, dbName, collName string) (*mongo.Collection, error) {
	client, ok := getMongoClientForTest(s, connName)
	if !ok {
		return nil, assert.AnError
	}
	return client.Database(dbName).Collection(collName), nil
}

// Helper to skip tests when running in short mode
func skipIfShort(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}
}

// Create a mock logger for testing
func setupMockLogger() EpicServer.Logger {
	return EpicServer.NewLogger(io.Discard, EpicServer.LogLevelInfo, EpicServer.LogFormatText)
}

func TestWithMongo(t *testing.T) {
	// Skip if we're not running in a CI environment with proper DB access
	if os.Getenv("CI_TEST_DB") != "true" {
		t.Skip("Skipping database tests in non-CI environment")
	}

	// Create a mock logger
	mockLogger := setupMockLogger()

	tests := []struct {
		name        string
		mongoConfig *MongoConfig
		wantError   bool
	}{
		{
			name: "invalid connection string",
			mongoConfig: &MongoConfig{
				ConnectionName: "test_invalid",
				URI:            "mongodb://invalid-host:27017",
				DatabaseName:   "test",
			},
			wantError: true,
		},
		{
			name: "localhost connection - requires local MongoDB",
			mongoConfig: &MongoConfig{
				ConnectionName: "test_local",
				URI:            "mongodb://localhost:27017",
				DatabaseName:   "test",
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &EpicServer.Server{
				Db:     make(map[string]interface{}),
				Logger: mockLogger,
			}

			appLayer := WithMongo(tt.mongoConfig)
			appLayer(s)

			// Verify the connection or error was stored
			assert.Contains(t, s.Db, tt.mongoConfig.ConnectionName)

			// Check if we got an error as expected
			if tt.wantError {
				_, ok := s.Db[tt.mongoConfig.ConnectionName].(*ErrMongoConnection)
				assert.True(t, ok, "Expected ErrMongoConnection but got different type")
			} else {
				config, ok := s.Db[tt.mongoConfig.ConnectionName].(*MongoConfig)
				assert.True(t, ok, "Expected MongoConfig but got different type")
				assert.NotNil(t, config.client)
			}
		})
	}
}

func TestGetMongoClient(t *testing.T) {
	// Create a mock logger
	mockLogger := setupMockLogger()

	s := &EpicServer.Server{
		Db:     make(map[string]interface{}),
		Logger: mockLogger,
	}

	// Setup a mock MongoDB config
	mongoConfig := &MongoConfig{
		ConnectionName: "test_get",
		URI:            "mongodb://localhost:27017",
		DatabaseName:   "test",
		client:         &mongo.Client{},
	}

	// Store the config without connecting
	s.Db[mongoConfig.ConnectionName] = mongoConfig

	// Store an error for another test
	s.Db["test_error"] = &ErrMongoConnection{
		URI: "mongodb://error:27017",
		Err: assert.AnError,
	}

	// Store an invalid type for another test
	s.Db["wrong_type"] = "not a mongo config"

	tests := []struct {
		name           string
		connectionName string
		wantOk         bool
	}{
		{
			name:           "valid connection",
			connectionName: "test_get",
			wantOk:         true,
		},
		{
			name:           "connection with error",
			connectionName: "test_error",
			wantOk:         false,
		},
		{
			name:           "nonexistent connection",
			connectionName: "nonexistent",
			wantOk:         false,
		},
		{
			name:           "wrong type",
			connectionName: "wrong_type",
			wantOk:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, ok := GetMongoClient(s, tt.connectionName)
			assert.Equal(t, tt.wantOk, ok)
			if tt.wantOk {
				assert.NotNil(t, client)
			} else {
				assert.Nil(t, client)
			}
		})
	}
}

func TestGetMongoCollection(t *testing.T) {
	// Skip integration tests unless running in CI
	if os.Getenv("CI_TEST_DB") != "true" {
		t.Skip("Skipping database tests in non-CI environment")
	}

	// Create a mock logger
	mockLogger := setupMockLogger()

	s := &EpicServer.Server{
		Db:     make(map[string]interface{}),
		Logger: mockLogger,
	}

	// Mock the client for collection test
	ctx := context.Background()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		t.Skip("Could not connect to local MongoDB")
	}

	mongoConfig := &MongoConfig{
		ConnectionName: "test_collection",
		URI:            "mongodb://localhost:27017",
		DatabaseName:   "test",
		client:         client,
	}

	s.Db[mongoConfig.ConnectionName] = mongoConfig

	// Test with invalid connection name
	t.Run("invalid connection name", func(t *testing.T) {
		_, err := GetMongoCollection(s, "nonexistent", "test", "test_collection")
		assert.Error(t, err)
	})

	// Test with valid connection
	t.Run("valid collection", func(t *testing.T) {
		coll, err := GetMongoCollection(s, "test_collection", "test", "test_collection")
		assert.NoError(t, err)
		assert.NotNil(t, coll)
	})
}

func TestUpdateIndexes(t *testing.T) {
	// Skip integration tests unless running in CI
	if os.Getenv("CI_TEST_DB") != "true" {
		t.Skip("Skipping database tests in non-CI environment")
	}

	ctx := context.Background()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		t.Skip("Could not connect to local MongoDB")
	}

	coll := client.Database("test").Collection("test_indexes")

	// Create some test indexes
	indexes := []mongo.IndexModel{
		{
			Keys: map[string]interface{}{"test_field": 1},
		},
	}

	err = UpdateIndexes(ctx, coll, indexes)
	assert.NoError(t, err)
}

func TestStringToObjectIDAndArray(t *testing.T) {
	// Test valid ObjectID
	validID := "507f1f77bcf86cd799439011"
	objID := StringToObjectID(validID)
	assert.Equal(t, validID, objID.Hex())

	// Test with invalid ID (should not panic)
	invalidID := StringToObjectID("invalid")
	assert.NotEqual(t, "invalid", invalidID.Hex())

	// Test with array of IDs
	testIDs := []string{
		"507f1f77bcf86cd799439011",
		"507f1f77bcf86cd799439012",
		"507f1f77bcf86cd799439013",
	}

	objIDs := StringArrayToObjectIDArray(testIDs)
	assert.Len(t, objIDs, len(testIDs))

	// Test with empty array
	emptyIDs := StringArrayToObjectIDArray([]string{})
	assert.Len(t, emptyIDs, 0)

	// Test with invalid ObjectID (should not panic)
	invalidIDs := StringArrayToObjectIDArray([]string{"invalid"})
	assert.Len(t, invalidIDs, 1)
}

func TestStringArrayContains(t *testing.T) {
	testArray := []string{"one", "two", "three"}

	// Test with value in array
	assert.True(t, StringArrayContains(testArray, "two"))

	// Test with value not in array
	assert.False(t, StringArrayContains(testArray, "four"))

	// Test with empty array
	assert.False(t, StringArrayContains([]string{}, "test"))
}

func TestErrMongoConnection(t *testing.T) {
	err := &ErrMongoConnection{
		URI: "mongodb://localhost:27017",
		Err: assert.AnError,
	}

	errMsg := err.Error()
	assert.Contains(t, errMsg, "mongodb://localhost:27017")
	assert.Contains(t, errMsg, "failed to connect to MongoDB")
}
