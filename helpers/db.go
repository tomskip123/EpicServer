package helpers

import (
	"context"
	"time"

	"github.com/cyberthy/server/db"
	"github.com/cyberthy/server/structs"
)

func SetupDatabase(ctx context.Context, databaseRef *structs.DB, dbConfig *structs.DbConfig) {
	databaseName := dbConfig.DbName

	if len(databaseName) <= 0 {
		panic("please add DATABASE_NAME env var")
	}

	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	databaseRef.Connect(ctx, dbConfig.DbUri)
	database := databaseRef.Client.Database(databaseName)

	user := &db.User{}
	user.Collection = database.Collection("users")

	databaseRef.SystemCollections = &structs.Collections{
		User: user,
	}

	user.CheckIndexes(ctx)
}

func RouteSkipsAuthMiddleware(app *structs.App, path string, staticRoutes []string) bool {
	for _, route := range staticRoutes {
		if path == route {
			return true
		}
	}

	for _, route := range app.ServerConfig.RouteSkipAuth {
		if path == route {
			return true
		}
	}

	return false
}
