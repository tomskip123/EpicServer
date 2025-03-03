// Package EpicServerDb provides database adapters for the EpicServer framework.
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
type MongoConfig struct {
	// ConnectionName is a unique identifier for this database connection
	ConnectionName string
	// URI is the MongoDB connection string
	URI string
	// DatabaseName is the name of the database to connect to
	DatabaseName string
	client       *mongo.Client
}

// ErrMongoConnection is returned when a MongoDB connection cannot be established
type ErrMongoConnection struct {
	URI string
	Err error
}

func (e *ErrMongoConnection) Error() string {
	return fmt.Sprintf("failed to connect to MongoDB at %s: %v", e.URI, e.Err)
}

// WithMongo creates a MongoDB connection and adds it to the server's database pool.
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
