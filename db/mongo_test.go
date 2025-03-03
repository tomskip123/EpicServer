package EpicServerDb

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tomskip123/EpicServer/v2"
	"go.mongodb.org/mongo-driver/mongo"
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

// Create a mock logger for testing
func setupMockLogger() EpicServer.Logger {
	return EpicServer.NewLogger(io.Discard, EpicServer.LogLevelInfo, EpicServer.LogFormatText)
}

// TestWithMongo tests the WithMongo function
func TestWithMongo(t *testing.T) {
	// Skip this test as it requires network connectivity
	t.Skip("Skipping TestWithMongo as it requires network connectivity")
}

// TestGetMongoClient tests the GetMongoClient function
func TestGetMongoClient(t *testing.T) {
	// Create a server
	s := &EpicServer.Server{
		Db:     make(map[string]interface{}),
		Logger: &testLogger{},
	}

	// Add a mock client
	mockClient := &mongo.Client{}
	config := &MongoConfig{
		ConnectionName: "test-mongo",
		URI:            "mongodb://localhost:27017",
		DatabaseName:   "test-db",
	}
	config.client = mockClient // Set the client directly
	s.Db["test-mongo"] = config

	// Test retrieving the client
	assert.NotPanics(t, func() {
		client := GetMongoClient(s, "test-mongo")
		assert.Equal(t, mockClient, client, "Should return the correct client")
	})

	// Test with non-existent client
	assert.Panics(t, func() {
		GetMongoClient(s, "non-existent")
	})

	// Test with error stored
	s.Db["error-mongo"] = &ErrMongoConnection{
		URI: "mongodb://invalid-host:27017",
		Err: assert.AnError,
	}
	assert.Panics(t, func() {
		GetMongoClient(s, "error-mongo")
	})

	// Test with wrong type
	s.Db["wrong-type"] = "not a mongo config"
	assert.Panics(t, func() {
		GetMongoClient(s, "wrong-type")
	})
}

// TestGetMongoCollection tests the GetMongoCollection function
func TestGetMongoCollection(t *testing.T) {
	// Since this function requires an actual MongoDB connection,
	// we'll just test the error paths
	s := &EpicServer.Server{
		Db:     make(map[string]interface{}),
		Logger: &testLogger{},
	}

	// Test with non-existent connection
	assert.Panics(t, func() {
		GetMongoCollection(s, "non-existent", "test-collection")
	})

	// Test with wrong type
	s.Db["wrong-type"] = "not a mongo config"
	assert.Panics(t, func() {
		GetMongoCollection(s, "wrong-type", "test-collection")
	})
}

// TestStringToObjectIDAndArray tests the StringToObjectID and StringArrayToObjectIDArray functions
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

// TestErrMongoConnection tests the ErrMongoConnection type
func TestErrMongoConnection(t *testing.T) {
	// Create an error
	err := &ErrMongoConnection{
		Err: assert.AnError,
	}

	// Test the Error method
	errMsg := err.Error()
	assert.Contains(t, errMsg, "failed to connect to MongoDB")
}

// Mock function for mongo.Connect
var mongoConnect = mongo.Connect
