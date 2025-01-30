package EpicServerDb

import (
	"fmt"

	"github.com/tomskip123/EpicServer"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type GormConfig struct {
	ConnectionName string
	Dialect        string // "mysql", "postgres", or "sqlite"
	DSN            string
	client         *gorm.DB
}

func WithGorm(gormConfig *GormConfig) EpicServer.AppLayer {
	return func(s *EpicServer.Server) {
		var db *gorm.DB
		var err error

		switch gormConfig.Dialect {
		case "mysql":
			db, err = gorm.Open(mysql.Open(gormConfig.DSN), &gorm.Config{})
		case "postgres":
			db, err = gorm.Open(postgres.Open(gormConfig.DSN), &gorm.Config{})
		case "sqlite":
			db, err = gorm.Open(sqlite.Open(gormConfig.DSN), &gorm.Config{})
		default:
			panic(fmt.Sprintf("unsupported dialect: %s", gormConfig.Dialect))
		}

		if err != nil {
			panic(fmt.Sprintf("failed to connect to database: %v", err))
		}

		gormConfig.client = db
		s.Db[gormConfig.ConnectionName] = gormConfig
	}
}

// GetGormDB safely retrieves the gorm.DB from the server
func GetGormDB(s *EpicServer.Server, connectionName string) *gorm.DB {
	if config, ok := s.Db[connectionName].(*GormConfig); ok {
		return config.client
	}
	panic("server DB is not a GORM client")
}

// AutoMigrateModels runs GORM AutoMigrate for the given models
func AutoMigrateModels(s *EpicServer.Server, connectionName string, models ...interface{}) error {
	db := GetGormDB(s, connectionName)
	return db.AutoMigrate(models...)
}
