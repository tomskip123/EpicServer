package epicserver

import (
	"errors"
	"log"
	"time"

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

	log.Println("Successful pinged pooler database")

	if es.Config.Database.QueryCacheEnabled {
		ttl := parseQueryCacheTTL(es.Config.Database.QueryCacheTTL)
		cache := newQueryCache(ttl, es.Config.Database.QueryCacheMaxEntries)
		if err := db.Use(newQueryCachePlugin(cache, es.Config.Logger.IsDebug)); err != nil {
			return nil, err
		}
	}

	es.Client = db
	return es, err
}

func parseQueryCacheTTL(raw string) time.Duration {
	if raw == "" {
		return 30 * time.Second
	}

	ttl, err := time.ParseDuration(raw)
	if err != nil || ttl <= 0 {
		log.Printf("invalid query cache ttl %q, falling back to 30s", raw)
		return 30 * time.Second
	}
	return ttl
}
