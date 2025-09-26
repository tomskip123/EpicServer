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

// we use gorm under the hood, so this is a lightweight direct connector to gorm.
// lets extend the gorm.DB
type EpicServerDatabase struct {
	Config *config.Config
	Client *gorm.DB
}

type EpicServerModel struct {
	gorm.Model
}

// here we should add more support for other databases.
func (es *EpicServerDatabase) Connect() (*EpicServerDatabase, error) {
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

	log.Println("Successful pinged database")

	es.Client = db

	return es, err
}
