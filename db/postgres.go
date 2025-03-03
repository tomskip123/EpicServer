package EpicServerDb

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
	"github.com/tomskip123/EpicServer/v2"
)

type PostgresConfig struct {
	ConnectionName string
	Host           string
	Port           int
	User           string
	Password       string
	Database       string
	SSLMode        string
}

func WithPostgres(config PostgresConfig) EpicServer.AppLayer {
	return func(s *EpicServer.Server) {
		// Create module-based logger
		dbLogger := s.Logger.WithModule("db.postgres")

		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			config.Host,
			config.Port,
			config.User,
			config.Password,
			config.Database,
			config.SSLMode,
		)

		dbLogger.Debug("Connecting to PostgreSQL",
			EpicServer.F("connection_name", config.ConnectionName),
			EpicServer.F("host", config.Host),
			EpicServer.F("port", config.Port),
			EpicServer.F("database", config.Database))

		db, err := sql.Open("postgres", dsn)
		if err != nil {
			dbLogger.Error("Failed to open PostgreSQL connection",
				EpicServer.F("error", err.Error()))
			s.AddError(err)
			return
		}

		if err := db.Ping(); err != nil {
			dbLogger.Error("Failed to ping PostgreSQL",
				EpicServer.F("error", err.Error()))
			s.AddError(err)
			return
		}

		s.Db[config.ConnectionName] = db

		dbLogger.Info("PostgreSQL connection established",
			EpicServer.F("connection_name", config.ConnectionName),
			EpicServer.F("database", config.Database))
	}
}

func GetPostgresDB(s *EpicServer.Server, connectionName string) *sql.DB {
	if db, ok := s.Db[connectionName].(*sql.DB); ok {
		return db
	}
	panic("server DB is not a Postgres connection")
}
