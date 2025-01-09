package EpicServerDb

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/tomskip123/EpicServer"
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
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			config.User,
			config.Password,
			config.Host,
			config.Port,
			config.Database,
		)

		db, err := sql.Open("mysql", dsn)
		if err != nil {
			panic(err)
		}

		if err := db.Ping(); err != nil {
			panic(err)
		}

		s.Db[config.ConnectionName] = db
	}
}

func GetMySQLDB(s *EpicServer.Server, connectionName string) *sql.DB {
	if db, ok := s.Db[connectionName].(*sql.DB); ok {
		return db
	}
	panic("server DB is not a MySQL connection")
}
