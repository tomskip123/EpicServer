// Package EpicServerDb provides database adapters for the EpicServer framework.
package EpicServerDb

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/tomskip123/EpicServer"
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
func WithMongo(mongoConfig *MongoConfig) EpicServer.AppLayer {
	return func(s *EpicServer.Server) {
		ctx := context.Background()

		// Create client and connect
		client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoConfig.URI))
		if err != nil {
			s.Logger.Error(fmt.Sprintf("Failed to connect to MongoDB: %v", err))
			// Store the error in the server's state instead of panicking
			s.Db[mongoConfig.ConnectionName] = &ErrMongoConnection{URI: mongoConfig.URI, Err: err}
			return
		}

		// Ping to verify connection
		if err := client.Ping(ctx, nil); err != nil {
			s.Logger.Error(fmt.Sprintf("Failed to ping MongoDB: %v", err))
			// Store the error in the server's state instead of panicking
			s.Db[mongoConfig.ConnectionName] = &ErrMongoConnection{URI: mongoConfig.URI, Err: err}
			return
		}

		// Cast the mongo client to the server's db interface
		if db, ok := interface{}(client).(*mongo.Client); ok {
			mongoConfig.client = db
			s.Db[mongoConfig.ConnectionName] = mongoConfig
		} else {
			s.Logger.Error("mongo client does not implement DB interface")
			s.Db[mongoConfig.ConnectionName] = fmt.Errorf("mongo client does not implement DB interface")
		}
	}
}

// GetMongoClient safely retrieves the mongo.Client from the server
// Returns the client and a boolean indicating success
func GetMongoClient(s *EpicServer.Server, connectionName string) (*mongo.Client, bool) {
	if config, ok := s.Db[connectionName].(*MongoConfig); ok {
		return config.client, true
	}

	// Check if we have an error stored instead
	if err, ok := s.Db[connectionName].(error); ok {
		s.Logger.Error(fmt.Sprintf("Cannot get MongoDB client: %v", err))
	} else {
		s.Logger.Error(fmt.Sprintf("Cannot get MongoDB client: connection '%s' not found or is not a MongoDB connection", connectionName))
	}

	return nil, false
}

// GetMongoCollection gets a MongoDB collection with error handling
func GetMongoCollection(s *EpicServer.Server, connectionName string, databaseName string, collectionName string) (*mongo.Collection, error) {
	client, ok := GetMongoClient(s, connectionName)
	if !ok {
		return nil, fmt.Errorf("failed to get MongoDB client for connection: %s", connectionName)
	}
	return client.Database(databaseName).Collection(collectionName), nil
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
