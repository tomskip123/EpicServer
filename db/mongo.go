// Package EpicServerDb provides database adapters for the EpicServer framework.
// It includes implementations for MongoDB, PostgreSQL, MySQL, and GORM,
// allowing you to easily integrate different database systems with your application.
//
// This package handles connection management, query execution, and common database operations.
// Each database implementation provides its own adapter with specialized functionality.
//
// # MongoDB Example
//
//	import (
//	    "github.com/tomskip123/EpicServer/v2"
//	    "github.com/tomskip123/EpicServer/v2/db"
//	    "go.mongodb.org/mongo-driver/bson"
//	    "go.mongodb.org/mongo-driver/mongo"
//	)
//
//	// Configure MongoDB connection
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
//	        ConnectionName: "default",
//	        URI:           "mongodb://localhost:27017",
//	        DatabaseName:  "myapp",
//	    }),
//	})
//
//	// Use MongoDB in a handler
//	func GetUsers(c *gin.Context) {
//	    // Get MongoDB collection
//	    usersCollection := EpicServerDb.GetMongoCollection(server, "default", "users")
//
//	    // Execute a query
//	    cursor, err := usersCollection.Find(c.Request.Context(), bson.M{})
//	    if err != nil {
//	        c.JSON(500, gin.H{"error": "Database error"})
//	        return
//	    }
//	    defer cursor.Close(c.Request.Context())
//
//	    // Decode results
//	    var users []User
//	    if err := cursor.All(c.Request.Context(), &users); err != nil {
//	        c.JSON(500, gin.H{"error": "Error decoding users"})
//	        return
//	    }
//
//	    c.JSON(200, users)
//	}
package EpicServerDb

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/tomskip123/EpicServer/v2"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoConfig contains configuration for a MongoDB connection.
// This struct stores both the connection settings and the actual client instance.
//
// Example:
//
//	config := &EpicServerDb.MongoConfig{
//	    ConnectionName: "analytics",
//	    URI:            "mongodb://username:password@localhost:27017",
//	    DatabaseName:   "analytics_db",
//	}
type MongoConfig struct {
	// ConnectionName is a unique identifier for this database connection
	ConnectionName string
	// URI is the MongoDB connection string
	URI string
	// DatabaseName is the name of the database to connect to
	DatabaseName string
	client       *mongo.Client
}

// ErrMongoConnection is returned when a MongoDB connection cannot be established.
// It includes the connection URI and the underlying error for debugging.
type ErrMongoConnection struct {
	URI string
	Err error
}

func (e *ErrMongoConnection) Error() string {
	return fmt.Sprintf("failed to connect to MongoDB at %s: %v", e.URI, e.Err)
}

// WithMongo creates a MongoDB connection and adds it to the server's database pool.
// The connection is identified by the ConnectionName specified in the config,
// and can be retrieved later using GetMongoClient, GetMongoDatabase, or GetMongoCollection.
//
// The function performs connection validation by pinging the server. If the connection
// fails, an error is added to the server's error list.
//
// Example:
//
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServerDb.WithMongo(&EpicServerDb.MongoConfig{
//	        ConnectionName: "default",
//	        URI:           "mongodb://localhost:27017",
//	        DatabaseName:  "myapp",
//	    }),
//	})
//
// Then use it in your handlers:
//
//	func CreateItem(c *gin.Context) {
//	    collection := EpicServerDb.GetMongoCollection(server, "default", "items")
//	    result, err := collection.InsertOne(c.Request.Context(), item)
//	    // ...
//	}
func WithMongo(config *MongoConfig) EpicServer.AppLayer {
	return func(s *EpicServer.Server) {
		// Create module-based logger
		dbLogger := s.Logger.WithModule("db.mongo")

		dbLogger.Debug("Connecting to MongoDB",
			EpicServer.F("connection_name", config.ConnectionName),
			EpicServer.F("database", config.DatabaseName))

		// Set client options
		clientOptions := options.Client().ApplyURI(config.URI)

		// Connect to MongoDB
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, err := mongo.Connect(ctx, clientOptions)
		if err != nil {
			dbLogger.Error("Failed to connect to MongoDB",
				EpicServer.F("error", err.Error()),
				EpicServer.F("uri", config.URI))
			s.AddError(&ErrMongoConnection{URI: config.URI, Err: err})
			return
		}

		// Check the connection
		err = client.Ping(ctx, nil)
		if err != nil {
			dbLogger.Error("Failed to ping MongoDB",
				EpicServer.F("error", err.Error()),
				EpicServer.F("uri", config.URI))
			s.AddError(&ErrMongoConnection{URI: config.URI, Err: err})
			return
		}

		config.client = client
		s.Db[config.ConnectionName] = config

		dbLogger.Info("MongoDB connection established",
			EpicServer.F("connection_name", config.ConnectionName),
			EpicServer.F("database", config.DatabaseName))
	}
}

// GetMongoClient retrieves the MongoDB client from the server's database pool.
// Use this function when you need direct access to the MongoDB client for
// operations like creating transactions or accessing multiple databases.
//
// Example:
//
//	client := EpicServerDb.GetMongoClient(server, "default")
//	// Use the client directly for advanced operations
//	session, err := client.StartSession()
//	if err != nil {
//	    // Handle error
//	}
//	defer session.EndSession(context.Background())
func GetMongoClient(s *EpicServer.Server, connectionName string) *mongo.Client {
	if config, ok := s.Db[connectionName].(*MongoConfig); ok {
		return config.client
	}
	panic(fmt.Sprintf("MongoDB connection '%s' not found", connectionName))
}

// GetMongoDatabase retrieves a specific MongoDB database from the server's database pool.
func GetMongoDatabase(s *EpicServer.Server, connectionName string) *mongo.Database {
	if config, ok := s.Db[connectionName].(*MongoConfig); ok {
		return config.client.Database(config.DatabaseName)
	}
	panic(fmt.Sprintf("MongoDB connection '%s' not found", connectionName))
}

// GetMongoCollection retrieves a specific MongoDB collection from the server's database pool.
func GetMongoCollection(s *EpicServer.Server, connectionName string, collectionName string) *mongo.Collection {
	if config, ok := s.Db[connectionName].(*MongoConfig); ok {
		return config.client.Database(config.DatabaseName).Collection(collectionName)
	}
	panic(fmt.Sprintf("MongoDB connection '%s' not found", connectionName))
}

//  MONGO HELPERS

func UpdateIndexes(ctx context.Context, collection *mongo.Collection, indexModels []mongo.IndexModel) error {
	opts := options.CreateIndexes().SetMaxTime(time.Second * 10) // Max execution time for creating indexes

	// Create indexes in the collection
	indexNames, err := collection.Indexes().CreateMany(ctx, indexModels, opts)
	if err != nil {
		log.Printf("failed to create index %v", err)
		return fmt.Errorf("failed to create indexes: %v", err)
	}

	log.Printf("Indexes created: %v\n", indexNames)
	return nil
}

func StringArrayToObjectIDArray(stringArray []string) []primitive.ObjectID {
	var newArray []primitive.ObjectID
	for _, s := range stringArray {
		objId, _ := primitive.ObjectIDFromHex(s)
		newArray = append(newArray, objId)
	}

	return newArray
}

func StringToObjectID(id string) primitive.ObjectID {
	objId, _ := primitive.ObjectIDFromHex(id)
	return objId
}

func StringArrayContains(strArray []string, contains string) bool {
	for _, a := range strArray {
		if a == contains {
			return true
		}
	}
	return false
}
