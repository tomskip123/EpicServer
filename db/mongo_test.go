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

// Mock logger for testing
type testLogger struct{}

func (l *testLogger) Debug(msg string, fields ...EpicServer.LogField) {}
func (l *testLogger) Info(msg string, fields ...EpicServer.LogField)  {}
func (l *testLogger) Warn(msg string, fields ...EpicServer.LogField)  {}
func (l *testLogger) Error(msg string, fields ...EpicServer.LogField) {}
func (l *testLogger) Fatal(msg string, fields ...EpicServer.LogField) {}
func (l *testLogger) WithFields(fields ...EpicServer.LogField) EpicServer.Logger {
	return l
}
func (l *testLogger) SetOutput(io.Writer)            {}
func (l *testLogger) SetLevel(EpicServer.LogLevel)   {}
func (l *testLogger) SetFormat(EpicServer.LogFormat) {}

// TestWithMongo tests the WithMongo function
func TestWithMongo(t *testing.T) {
	// Create a server
	s := &EpicServer.Server{
		Db:     make(map[string]interface{}),
		Logger: &testLogger{},
	}

	// Test with invalid URI (this will generate an error)
	config := &MongoConfig{
		ConnectionName: "test-mongo",
		URI:            "mongodb://invalid-host:27017",
		DatabaseName:   "test-db",
	}

	// Create the app layer
	appLayer := WithMongo(config)

	// Apply the layer - this should store an error in the server's state
	appLayer(s)

	// Verify error was stored
	result, ok := s.Db["test-mongo"]
	assert.True(t, ok, "Should store connection result in server's Db map")

	// The result should be an error
	err, ok := result.(*ErrMongoConnection)
	assert.True(t, ok, "Should store an ErrMongoConnection for invalid connection")
	assert.Contains(t, err.Error(), "failed to connect to MongoDB", "Error should mention connection failure")
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
	client, ok := GetMongoClient(s, "test-mongo")
	assert.True(t, ok, "Should find the client")
	assert.Equal(t, mockClient, client, "Should return the correct client")

	// Test with non-existent client
	client, ok = GetMongoClient(s, "non-existent")
	assert.False(t, ok, "Should not find non-existent client")
	assert.Nil(t, client, "Should return nil for non-existent client")

	// Test with error stored
	s.Db["error-mongo"] = &ErrMongoConnection{
		URI: "mongodb://invalid-host:27017",
		Err: assert.AnError,
	}
	client, ok = GetMongoClient(s, "error-mongo")
	assert.False(t, ok, "Should indicate failure for error connection")
	assert.Nil(t, client, "Should return nil for error connection")

	// Test with wrong type
	s.Db["wrong-type"] = "not a mongo config"
	client, ok = GetMongoClient(s, "wrong-type")
	assert.False(t, ok, "Should indicate failure for wrong type")
	assert.Nil(t, client, "Should return nil for wrong type")
}

// TestGetMongoCollection tests the GetMongoCollection function
func TestGetMongoCollection(t *testing.T) {
	// Since this function requires an actual MongoDB connection,
	// we'll just test the error paths

	// Create a server
	s := &EpicServer.Server{
		Db:     make(map[string]interface{}),
		Logger: &testLogger{},
	}

	// Mock the GetMongoClient function to avoid the nil pointer dereference
	// We'll directly test the error cases without calling the real function

	// Test with non-existent client
	collection, err := GetMongoCollection(s, "non-existent", "test-db", "test-collection")
	assert.Error(t, err, "Should return error for non-existent client")
	assert.Nil(t, collection, "Should return nil collection for non-existent client")

	// Test with error stored
	s.Db["error-mongo"] = &ErrMongoConnection{
		URI: "mongodb://invalid-host:27017",
		Err: assert.AnError,
	}
	collection, err = GetMongoCollection(s, "error-mongo", "test-db", "test-collection")
	assert.Error(t, err, "Should return error for error connection")
	assert.Nil(t, collection, "Should return nil collection for error connection")
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
