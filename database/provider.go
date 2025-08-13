package database

import (
	"fmt"

	"github.com/tech-arch1tect/brx/config"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type ModelsOption struct {
	models []any
}

func WithModels(models ...any) *ModelsOption {
	return &ModelsOption{models: models}
}

func ProvideDatabase(cfg config.Config, modelsOpt *ModelsOption) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	switch cfg.Database.Driver {
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(cfg.Database.DSN), &gorm.Config{})
	case "postgres", "postgresql":
		db, err = gorm.Open(postgres.Open(cfg.Database.DSN), &gorm.Config{})
	case "mysql":
		db, err = gorm.Open(mysql.Open(cfg.Database.DSN), &gorm.Config{})
	default:
		return nil, fmt.Errorf("unsupported database driver: %s (supported: sqlite, postgres, mysql)", cfg.Database.Driver)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if cfg.Database.AutoMigrate && modelsOpt != nil && len(modelsOpt.models) > 0 {
		if err := db.AutoMigrate(modelsOpt.models...); err != nil {
			return nil, fmt.Errorf("failed to auto-migrate models: %w", err)
		}
	}

	return db, nil
}
