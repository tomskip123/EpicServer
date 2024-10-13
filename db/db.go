package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DB interface {
}

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
