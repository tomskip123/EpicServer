package EpicServerDb

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/tomskip123/EpicServer/v2"
)

type MySQLConfig struct {
	ConnectionName string
	Host           string
	Port           int
	User           string
	Password       string
	Database       string
}

func WithMySQL(config MySQLConfig) EpicServer.AppLayer {
	return func(s *EpicServer.Server) {
		// Create module-based logger
		dbLogger := s.Logger.WithModule("db.mysql")

		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			config.User,
			config.Password,
			config.Host,
			config.Port,
			config.Database,
		)

		dbLogger.Debug("Connecting to MySQL",
			EpicServer.F("connection_name", config.ConnectionName),
			EpicServer.F("host", config.Host),
			EpicServer.F("port", config.Port),
			EpicServer.F("database", config.Database))

		db, err := sql.Open("mysql", dsn)
		if err != nil {
			dbLogger.Error("Failed to open MySQL connection",
				EpicServer.F("error", err.Error()))
			s.AddError(err)
			return
		}

		if err := db.Ping(); err != nil {
			dbLogger.Error("Failed to ping MySQL",
				EpicServer.F("error", err.Error()))
			s.AddError(err)
			return
		}

		s.Db[config.ConnectionName] = db

		dbLogger.Info("MySQL connection established",
			EpicServer.F("connection_name", config.ConnectionName),
			EpicServer.F("database", config.Database))
	}
}

func GetMySQLDB(s *EpicServer.Server, connectionName string) *sql.DB {
	if db, ok := s.Db[connectionName].(*sql.DB); ok {
		return db
	}
	panic("server DB is not a MySQL connection")
}
