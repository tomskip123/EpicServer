package epicserver

import (
	"errors"
	"log"

	"github.com/tomskip123/EpicServer/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	DatabaseEmptyConnectionString = "empty_dsn"
)

// EpicServerDatabaseWith keeps a reference to the application's config so
// downstream features can work with the caller's custom fields.
type EpicServerDatabaseWith[T any] struct {
	Config *config.ConfigWith[T]
	Client *gorm.DB
}

// EpicServerDatabase maintains the previous non-generic identifier.
type EpicServerDatabase = EpicServerDatabaseWith[struct{}]

type EpicServerModel struct {
	gorm.Model
}

// Connect currently supports postgres and validates connectivity before
// returning the database handle.
func (es *EpicServerDatabaseWith[T]) Connect() (*EpicServerDatabaseWith[T], error) {
	if es.Config.Database.DSN == "" {
		return nil, errors.New(DatabaseEmptyConnectionString)
	}

	driver := es.Config.Database.Driver
	log.Printf("Using Database driver: %v \n", driver)

	db, err := gorm.Open(postgres.Open(es.Config.Database.DSN), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	dbClient, err := db.DB()
	if err != nil {
		return nil, err
	}

	if err := dbClient.Ping(); err != nil {
		return nil, err
	}

	log.Println("Successful pinged pooler database")

	es.Client = db
	return es, err
}
