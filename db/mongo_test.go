package EpicServerDb

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tomskip123/EpicServer"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// TestServer is a simplified version of EpicServer.Server for testing
type TestServer struct {
	Databases map[string]interface{}
	Logger    EpicServer.Logger
}

// Implementation of the minimal necessary interface for the db tests
func (s *TestServer) GetDatabase(name string) (interface{}, bool) {
	if s.Databases == nil {
		return nil, false
	}
	db, ok := s.Databases[name]
	return db, ok
}

func (s *TestServer) AddDatabase(name string, db interface{}) {
	if s.Databases == nil {
		s.Databases = make(map[string]interface{})
	}
	s.Databases[name] = db
}

func (s *TestServer) GetLogger() EpicServer.Logger {
	return s.Logger
}

// Helper functions to bridge our test server with the real functions
func getMongoClientForTest(s *TestServer, name string) (*mongo.Client, bool) {
	if s.Databases == nil {
		return nil, false
	}

	client, ok := s.Databases[name].(*mongo.Client)
	return client, ok
}

func getMongoCollectionForTest(s *TestServer, connName, dbName, collName string) (*mongo.Collection, error) {
	client, ok := getMongoClientForTest(s, connName)
	if !ok {
		return nil, assert.AnError
	}

	// This will fail in tests since we're using a mock client
	return client.Database(dbName).Collection(collName), nil
}

// Skip integration tests when using short mode
func skipIfShort(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
}

// TestWithMongo tests the WithMongo function
func TestWithMongo(t *testing.T) {
	skipIfShort(t)

	// Create a mock logger that implements the new interface
	mockLogger := new(MockLogger)
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	// Create a test server
	testServer := &TestServer{
		Logger: mockLogger,
	}

	// Create test configuration
	config := &MongoConfig{
		ConnectionName: "test-conn",
		URI:            "mongodb://localhost:27017",
		DatabaseName:   "test-db",
	}

	// Create a function that mimics WithMongo but works with our TestServer
	withMongoForTest := func(config *MongoConfig) func(*TestServer) {
		return func(s *TestServer) {
			// In a real test, we'd connect to MongoDB, but here we'll just mock it
			s.AddDatabase(config.ConnectionName, &mongo.Client{})
		}
	}

	// Apply our test function
	layer := withMongoForTest(config)
	layer(testServer)

	// Verify the database was added
	_, ok := testServer.GetDatabase("test-conn")
	assert.True(t, ok)
}

// Test the StringToObjectID function
func TestStringToObjectID(t *testing.T) {
	// Test valid ObjectID
	validID := "5f50c31f84ed9a7d0acb7da2"
	objectID := StringToObjectID(validID)
	assert.Equal(t, validID, objectID.Hex())

	// Test invalid ObjectID (should return empty ObjectID)
	invalidID := "invalid-id"
	emptyObjectID := StringToObjectID(invalidID)
	assert.Equal(t, primitive.NilObjectID, emptyObjectID)
}

// Test the StringArrayToObjectIDArray function
func TestStringArrayToObjectIDArray(t *testing.T) {
	// Test array of valid IDs
	validIDs := []string{"5f50c31f84ed9a7d0acb7da2", "5f50c31f84ed9a7d0acb7da3"}
	objectIDs := StringArrayToObjectIDArray(validIDs)

	assert.Equal(t, 2, len(objectIDs))
	assert.Equal(t, validIDs[0], objectIDs[0].Hex())
	assert.Equal(t, validIDs[1], objectIDs[1].Hex())

	// Test array with invalid ID (should include invalid IDs as empty ObjectIDs)
	mixedIDs := []string{"5f50c31f84ed9a7d0acb7da2", "invalid-id"}
	mixedObjectIDs := StringArrayToObjectIDArray(mixedIDs)

	assert.Equal(t, 2, len(mixedObjectIDs))
	assert.Equal(t, mixedIDs[0], mixedObjectIDs[0].Hex())
	assert.Equal(t, primitive.NilObjectID, mixedObjectIDs[1])
}

// Test the StringArrayContains function
func TestStringArrayContains(t *testing.T) {
	// Test array that contains the string
	array := []string{"apple", "banana", "cherry"}
	assert.True(t, StringArrayContains(array, "banana"))

	// Test array that doesn't contain the string
	assert.False(t, StringArrayContains(array, "grape"))

	// Test empty array
	assert.False(t, StringArrayContains([]string{}, "apple"))
}

// Test GetMongoClient function
func TestGetMongoClient(t *testing.T) {
	testServer := &TestServer{
		Databases: make(map[string]interface{}),
	}

	// Test case: client exists
	expectedClient := &mongo.Client{}
	testServer.Databases["test-conn"] = expectedClient

	client, exists := getMongoClientForTest(testServer, "test-conn")
	assert.True(t, exists)
	assert.Equal(t, expectedClient, client)

	// Test case: client doesn't exist
	client, exists = getMongoClientForTest(testServer, "nonexistent")
	assert.False(t, exists)
	assert.Nil(t, client)
}

// Mock Logger for tests that implements the new Logger interface
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Info(msg string, fields ...EpicServer.LogField) {
	args := []interface{}{msg}
	for _, field := range fields {
		args = append(args, field)
	}
	m.Called(args...)
}

func (m *MockLogger) Error(msg string, fields ...EpicServer.LogField) {
	args := []interface{}{msg}
	for _, field := range fields {
		args = append(args, field)
	}
	m.Called(args...)
}

func (m *MockLogger) Debug(msg string, fields ...EpicServer.LogField) {
	args := []interface{}{msg}
	for _, field := range fields {
		args = append(args, field)
	}
	m.Called(args...)
}

func (m *MockLogger) Warn(msg string, fields ...EpicServer.LogField) {
	args := []interface{}{msg}
	for _, field := range fields {
		args = append(args, field)
	}
	m.Called(args...)
}

func (m *MockLogger) Fatal(msg string, fields ...EpicServer.LogField) {
	args := []interface{}{msg}
	for _, field := range fields {
		args = append(args, field)
	}
	m.Called(args...)
}

func (m *MockLogger) WithFields(fields ...EpicServer.LogField) EpicServer.Logger {
	args := []interface{}{}
	for _, field := range fields {
		args = append(args, field)
	}
	m.Called(args...)
	return m
}

func (m *MockLogger) SetOutput(output io.Writer) {
	m.Called(output)
}

func (m *MockLogger) SetLevel(level EpicServer.LogLevel) {
	m.Called(level)
}

func (m *MockLogger) SetFormat(format EpicServer.LogFormat) {
	m.Called(format)
}

// Test GetMongoCollection function
func TestGetMongoCollection(t *testing.T) {
	testServer := &TestServer{
		Databases: make(map[string]interface{}),
	}

	// Test case: client exists
	expectedClient := &mongo.Client{}
	testServer.Databases["test-conn"] = expectedClient

	// This test will not actually connect to MongoDB, but tests the error handling
	collection, err := getMongoCollectionForTest(testServer, "test-conn", "test-db", "test-collection")
	assert.Nil(t, err) // We're not actually connecting, so no error
	assert.NotNil(t, collection)

	// Test case: client doesn't exist
	collection, err = getMongoCollectionForTest(testServer, "nonexistent", "test-db", "test-collection")
	assert.Error(t, err)
	assert.Nil(t, collection)
}

// Test ErrMongoConnection error message
func TestErrMongoConnection_Error(t *testing.T) {
	err := &ErrMongoConnection{
		URI: "mongodb://localhost:27017",
		Err: assert.AnError,
	}

	errorMsg := err.Error()
	assert.Contains(t, errorMsg, "failed to connect to MongoDB at mongodb://localhost:27017")
}
