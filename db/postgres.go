package db

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
	"github.com/tomskip123/EpicServer"
)

type PostgresConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string
}

func WithPostgres(config PostgresConfig) EpicServer.AppLayer {
	return func(s *EpicServer.Server) {
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			config.Host,
			config.Port,
			config.User,
			config.Password,
			config.Database,
			config.SSLMode,
		)

		db, err := sql.Open("postgres", dsn)
		if err != nil {
			panic(err)
		}

		if err := db.Ping(); err != nil {
			panic(err)
		}

		s.Db = db
	}
}

func GetPostgresDB(s *EpicServer.Server) *sql.DB {
	if db, ok := s.Db.(*sql.DB); ok {
		return db
	}
	panic("server DB is not a Postgres connection")
}
