package EpicServerDb

import (
	"fmt"

	"github.com/tomskip123/EpicServer/v2"
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
		// Create module-based logger
		dbLogger := s.Logger.WithModule("db.gorm")

		dbLogger.Debug("Connecting to database with GORM",
			EpicServer.F("connection_name", gormConfig.ConnectionName),
			EpicServer.F("dialect", gormConfig.Dialect),
			EpicServer.F("dsn", gormConfig.DSN))

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
			errMsg := fmt.Sprintf("unsupported dialect: %s", gormConfig.Dialect)
			dbLogger.Error("GORM initialization failed",
				EpicServer.F("error", errMsg))
			s.AddError(fmt.Errorf(errMsg))
			return
		}

		if err != nil {
			dbLogger.Error("Failed to connect to database with GORM",
				EpicServer.F("error", err.Error()),
				EpicServer.F("dialect", gormConfig.Dialect))
			s.AddError(err)
			return
		}

		gormConfig.client = db
		s.Db[gormConfig.ConnectionName] = gormConfig

		dbLogger.Info("GORM connection established",
			EpicServer.F("connection_name", gormConfig.ConnectionName),
			EpicServer.F("dialect", gormConfig.Dialect))
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
	// Create module-based logger
	dbLogger := s.Logger.WithModule("db.gorm")

	db := GetGormDB(s, connectionName)

	dbLogger.Debug("Running GORM AutoMigrate",
		EpicServer.F("connection_name", connectionName),
		EpicServer.F("model_count", len(models)))

	err := db.AutoMigrate(models...)

	if err != nil {
		dbLogger.Error("GORM AutoMigrate failed",
			EpicServer.F("error", err.Error()),
			EpicServer.F("connection_name", connectionName))
	} else {
		dbLogger.Info("GORM AutoMigrate completed successfully",
			EpicServer.F("connection_name", connectionName))
	}

	return err
}
