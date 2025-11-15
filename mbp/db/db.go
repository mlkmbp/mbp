package db

import (
	"errors"
	"gorm.io/driver/mysql"
	sqlite "gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
	"mlkmbp/mbp/common/config"
	"mlkmbp/mbp/common/logx"
	"strings"
	"time"
)

var (
	ErrUnsupportedDriver = errors.New("unsupported driver")
)

type DB struct {
	GormDataSource *gorm.DB
	Driver         string
}

func OpenGorm(driver, dsn string, pool config.DBPoolCfg) (*DB, error) {
	var dial gorm.Dialector

	switch strings.ToLower(driver) {
	case "mysql":
		dial = mysql.Open(dsn)
	case "sqlite", "sqlite3":
		dial = sqlite.Open(dsn)
	default:
		return nil, ErrUnsupportedDriver
	}

	g, err := gorm.Open(dial, &gorm.Config{
		NamingStrategy: schema.NamingStrategy{SingularTable: true},
		Logger:         logx.GormLoggerDefault(logx.GetLevelString()),
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := g.DB()
	if err != nil {
		return nil, err
	}
	if pool.MaxOpen > 0 {
		sqlDB.SetMaxOpenConns(pool.MaxOpen)
	}
	if pool.MaxIdle > 0 {
		sqlDB.SetMaxIdleConns(pool.MaxIdle)
	}
	if pool.MaxLifetimeSec > 0 {
		sqlDB.SetConnMaxLifetime(time.Duration(pool.MaxLifetimeSec) * time.Second)
	}

	return &DB{GormDataSource: g, Driver: driver}, nil
}
