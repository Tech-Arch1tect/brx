package database

import (
	"fmt"
	"time"

	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/zap"
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

func ProvideDatabase(cfg config.Config, modelsOpt *ModelsOption, logger *logging.Service) (*gorm.DB, error) {
	if logger != nil {
		logger.Info("initializing database connection",
			zap.String("driver", cfg.Database.Driver),
			zap.Bool("auto_migrate", cfg.Database.AutoMigrate))
	}

	var db *gorm.DB
	var err error
	startTime := time.Now()

	switch cfg.Database.Driver {
	case "sqlite":
		if logger != nil {
			logger.Debug("connecting to SQLite database", zap.String("dsn", cfg.Database.DSN))
		}
		db, err = gorm.Open(sqlite.Open(cfg.Database.DSN), &gorm.Config{})
	case "postgres", "postgresql":
		if logger != nil {
			logger.Debug("connecting to PostgreSQL database")
		}
		db, err = gorm.Open(postgres.Open(cfg.Database.DSN), &gorm.Config{})
	case "mysql":
		if logger != nil {
			logger.Debug("connecting to MySQL database")
		}
		db, err = gorm.Open(mysql.Open(cfg.Database.DSN), &gorm.Config{})
	default:
		if logger != nil {
			logger.Error("unsupported database driver specified",
				zap.String("driver", cfg.Database.Driver),
				zap.Strings("supported_drivers", []string{"sqlite", "postgres", "mysql"}))
		}
		return nil, fmt.Errorf("unsupported database driver: %s (supported: sqlite, postgres, mysql)", cfg.Database.Driver)
	}

	if err != nil {
		if logger != nil {
			logger.Error("failed to connect to database",
				zap.Error(err),
				zap.String("driver", cfg.Database.Driver),
				zap.Duration("attempt_duration", time.Since(startTime)))
		}
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test the connection
	sqlDB, err := db.DB()
	if err != nil {
		if logger != nil {
			logger.Error("failed to get underlying sql.DB instance", zap.Error(err))
		}
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		if logger != nil {
			logger.Error("database connection test failed",
				zap.Error(err),
				zap.String("driver", cfg.Database.Driver))
		}
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	if logger != nil {
		logger.Info("database connection established successfully",
			zap.String("driver", cfg.Database.Driver),
			zap.Duration("connection_time", time.Since(startTime)))
	}

	// Handle auto-migration if enabled
	if cfg.Database.AutoMigrate && modelsOpt != nil && len(modelsOpt.models) > 0 {
		if logger != nil {
			logger.Info("starting auto-migration",
				zap.Int("model_count", len(modelsOpt.models)))
		}

		migrationStart := time.Now()
		if err := db.AutoMigrate(modelsOpt.models...); err != nil {
			if logger != nil {
				logger.Error("auto-migration failed",
					zap.Error(err),
					zap.Int("model_count", len(modelsOpt.models)),
					zap.Duration("migration_duration", time.Since(migrationStart)))
			}
			return nil, fmt.Errorf("failed to auto-migrate models: %w", err)
		}

		if logger != nil {
			logger.Info("auto-migration completed successfully",
				zap.Int("model_count", len(modelsOpt.models)),
				zap.Duration("migration_duration", time.Since(migrationStart)))
		}
	} else {
		if logger != nil {
			if !cfg.Database.AutoMigrate {
				logger.Debug("auto-migration disabled in configuration")
			} else {
				logger.Debug("no models provided for auto-migration")
			}
		}
	}

	return db, nil
}
