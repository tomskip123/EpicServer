package structs

import (
	"context"
	"fmt"
	"log"

	"github.com/cyberthy/server/db"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type CollectionInterface interface{}

type Collection struct {
	Collection     *mongo.Collection
	CollectionName string
}

type Collections struct {
	User *db.User
}

type DB struct {
	Client            *mongo.Client
	SystemCollections *Collections
	Collections       map[string]CollectionInterface
}

func (db *DB) GetCollectionOrPanic(colName string) CollectionInterface {
	if db.Collections[colName] == nil {
		log.Fatalf("expected *%v, but got %T", colName, db.Collections[colName])
	}

	return db.Collections[colName]
}

func (db *DB) Connect(ctx context.Context, uri string) {
	// Set client options
	clientOptions := options.Client().ApplyURI(uri)

	// Connect to MongoDB
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// Check the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")
	db.Client = client
}

func (db *DB) HandleDbDisconnect(ctx context.Context, database *DB) {
	fmt.Println("Attempting to disconnect from database...")
	if err := database.Client.Disconnect(ctx); err != nil {
		log.Fatalf("Error disconnecting from the database: %v", err)
	} else {
		fmt.Println("Successfully disconnected from the database.")
	}
}
