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

type MongoConfig struct {
	ConnectionName string
	URI            string
	DatabaseName   string
	client         *mongo.Client
}

func WithMongo(mongoConfig *MongoConfig) EpicServer.AppLayer {
	return func(s *EpicServer.Server) {
		ctx := context.Background()

		// Create client and connect
		client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoConfig.URI))
		if err != nil {
			panic(err)
		}

		// Ping to verify connection
		if err := client.Ping(ctx, nil); err != nil {
			panic(err)
		}

		// Cast the mongo client to the server's db interface
		if db, ok := interface{}(client).(*mongo.Client); ok {
			mongoConfig.client = db
			s.Db[mongoConfig.ConnectionName] = mongoConfig
		} else {
			panic("mongo client does not implement DB interface")
		}
	}
}

// GetMongoClient safely retrieves the mongo.Client from the server
func GetMongoClient(s *EpicServer.Server, connectionName string) *mongo.Client {
	if config, ok := s.Db[connectionName].(*MongoConfig); ok {
		return config.client
	}
	panic("server DB is not a mongo client")
}

// Nice Helper method for getting a collection
func GetMongoCollection(s *EpicServer.Server, connectionName string, databaseName string, collectionName string) *mongo.Collection {
	client := GetMongoClient(s, connectionName)
	return client.Database(databaseName).Collection(collectionName)
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
