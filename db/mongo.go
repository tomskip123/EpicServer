package db

import (
	"context"

	"github.com/tomskip123/EpicServer"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoConfig struct {
	URI string
}

func WithMongo(mongoConfig MongoConfig) EpicServer.AppLayer {
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
		if db, ok := interface{}(client).(mongo.Client); ok {
			s.Db = db
		} else {
			panic("mongo client does not implement DB interface")
		}
	}
}

// GetMongoClient safely retrieves the mongo.Client from the server
func GetMongoClient(s *EpicServer.Server) *mongo.Client {
	if client, ok := s.Db.(*mongo.Client); ok {
		return client
	}
	panic("server DB is not a mongo client")
}
