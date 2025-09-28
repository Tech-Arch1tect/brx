package database

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
)

func createTestConfig(driver, dsn string, autoMigrate bool) config.Config {
	return config.Config{
		Database: config.DatabaseConfig{
			Driver:      driver,
			DSN:         dsn,
			AutoMigrate: autoMigrate,
		},
	}
}

func newTestLogger() *logging.Service {
	logger, _ := logging.NewService(logging.Config{
		Level:      logging.Debug,
		Format:     "console",
		OutputPath: "stdout",
	})
	return logger
}

type TestModel struct {
	ID   uint   `gorm:"primaryKey"`
	Name string `gorm:"size:255"`
}

func TestWithModels(t *testing.T) {
	t.Run("with single model", func(t *testing.T) {
		model := TestModel{}
		option := WithModels(model)

		assert.NotNil(t, option)
		assert.Len(t, option.models, 1)
		assert.Equal(t, model, option.models[0])
	})

	t.Run("with multiple models", func(t *testing.T) {
		model1 := TestModel{}
		model2 := &TestModel{}
		option := WithModels(model1, model2)

		assert.NotNil(t, option)
		assert.Len(t, option.models, 2)
		assert.Equal(t, model1, option.models[0])
		assert.Equal(t, model2, option.models[1])
	})

	t.Run("with no models", func(t *testing.T) {
		option := WithModels()

		assert.NotNil(t, option)
		assert.Len(t, option.models, 0)
	})
}

func TestProvideDatabase_SQLite(t *testing.T) {
	t.Run("successful connection to in-memory SQLite", func(t *testing.T) {
		cfg := createTestConfig("sqlite", ":memory:", false)
		logger := newTestLogger()

		db, err := ProvideDatabase(cfg, nil, logger)

		assert.NoError(t, err)
		assert.NotNil(t, db)

		sqlDB, err := db.DB()
		require.NoError(t, err)
		assert.NoError(t, sqlDB.Ping())
		defer sqlDB.Close()
	})

	t.Run("successful connection to file-based SQLite", func(t *testing.T) {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "test.db")
		cfg := createTestConfig("sqlite", dbPath, false)
		logger := newTestLogger()

		db, err := ProvideDatabase(cfg, nil, logger)

		assert.NoError(t, err)
		assert.NotNil(t, db)

		sqlDB, err := db.DB()
		require.NoError(t, err)
		assert.NoError(t, sqlDB.Ping())
		defer sqlDB.Close()

		_, err = os.Stat(dbPath)
		assert.NoError(t, err)
	})

	t.Run("with auto-migration enabled and models", func(t *testing.T) {
		cfg := createTestConfig("sqlite", ":memory:", true)
		logger := newTestLogger()
		modelsOpt := WithModels(TestModel{})

		db, err := ProvideDatabase(cfg, modelsOpt, logger)

		assert.NoError(t, err)
		assert.NotNil(t, db)

		assert.True(t, db.Migrator().HasTable(&TestModel{}))

		sqlDB, err := db.DB()
		require.NoError(t, err)
		defer sqlDB.Close()
	})

	t.Run("with auto-migration disabled", func(t *testing.T) {
		cfg := createTestConfig("sqlite", ":memory:", false)
		logger := newTestLogger()
		modelsOpt := WithModels(TestModel{})

		db, err := ProvideDatabase(cfg, modelsOpt, logger)

		assert.NoError(t, err)
		assert.NotNil(t, db)

		assert.False(t, db.Migrator().HasTable(&TestModel{}))

		sqlDB, err := db.DB()
		require.NoError(t, err)
		defer sqlDB.Close()
	})

	t.Run("with auto-migration enabled but no models", func(t *testing.T) {
		cfg := createTestConfig("sqlite", ":memory:", true)
		logger := newTestLogger()

		db, err := ProvideDatabase(cfg, nil, logger)

		assert.NoError(t, err)
		assert.NotNil(t, db)

		sqlDB, err := db.DB()
		require.NoError(t, err)
		defer sqlDB.Close()
	})

	t.Run("with invalid SQLite path", func(t *testing.T) {
		cfg := createTestConfig("sqlite", "/nonexistent/directory/test.db", false)
		logger := newTestLogger()

		db, err := ProvideDatabase(cfg, nil, logger)

		assert.Error(t, err)
		assert.Nil(t, db)
		assert.Contains(t, err.Error(), "failed to connect to database")
	})
}

func TestProvideDatabase_UnsupportedDriver(t *testing.T) {
	t.Run("unsupported database driver", func(t *testing.T) {
		cfg := createTestConfig("unsupported", "test", false)
		logger := newTestLogger()

		db, err := ProvideDatabase(cfg, nil, logger)

		assert.Error(t, err)
		assert.Nil(t, db)
		assert.Contains(t, err.Error(), "unsupported database driver: unsupported")
		assert.Contains(t, err.Error(), "supported: sqlite, postgres, mysql")
	})

	t.Run("empty database driver", func(t *testing.T) {
		cfg := createTestConfig("", "test", false)
		logger := newTestLogger()

		db, err := ProvideDatabase(cfg, nil, logger)

		assert.Error(t, err)
		assert.Nil(t, db)
		assert.Contains(t, err.Error(), "unsupported database driver")
	})
}

func TestProvideDatabase_WithoutLogger(t *testing.T) {
	t.Run("successful connection without logger", func(t *testing.T) {
		cfg := createTestConfig("sqlite", ":memory:", false)

		db, err := ProvideDatabase(cfg, nil, nil)

		assert.NoError(t, err)
		assert.NotNil(t, db)

		sqlDB, err := db.DB()
		require.NoError(t, err)
		assert.NoError(t, sqlDB.Ping())
		defer sqlDB.Close()
	})

	t.Run("error case without logger", func(t *testing.T) {
		cfg := createTestConfig("unsupported", "test", false)

		db, err := ProvideDatabase(cfg, nil, nil)

		assert.Error(t, err)
		assert.Nil(t, db)
	})
}

func TestProvideDatabase_PostgreSQL(t *testing.T) {
	t.Run("postgresql driver name alias", func(t *testing.T) {
		cfg := createTestConfig("postgresql", "postgres://user:pass@localhost/test", false)
		logger := newTestLogger()

		db, err := ProvideDatabase(cfg, nil, logger)

		assert.Error(t, err)
		assert.Nil(t, db)
		assert.Contains(t, err.Error(), "failed to connect to database")
	})

	t.Run("postgres driver name", func(t *testing.T) {
		cfg := createTestConfig("postgres", "postgres://user:pass@localhost/test", false)
		logger := newTestLogger()

		db, err := ProvideDatabase(cfg, nil, logger)

		assert.Error(t, err)
		assert.Nil(t, db)
		assert.Contains(t, err.Error(), "failed to connect to database")
	})
}

func TestProvideDatabase_MySQL(t *testing.T) {
	t.Run("mysql driver", func(t *testing.T) {
		cfg := createTestConfig("mysql", "user:pass@tcp(localhost:3306)/test", false)
		logger := newTestLogger()

		db, err := ProvideDatabase(cfg, nil, logger)

		assert.Error(t, err)
		assert.Nil(t, db)
		assert.Contains(t, err.Error(), "failed to connect to database")
	})
}

func TestProvideDatabase_AutoMigrationFailure(t *testing.T) {
	t.Run("migration failure with invalid model containing channel", func(t *testing.T) {
		cfg := createTestConfig("sqlite", ":memory:", true)
		logger := newTestLogger()

		type InvalidChannelModel struct {
			ID      uint `gorm:"primaryKey"`
			Channel chan string
		}

		modelsOpt := WithModels(InvalidChannelModel{})

		db, err := ProvideDatabase(cfg, modelsOpt, logger)

		assert.Error(t, err)
		assert.Nil(t, db)
		assert.Contains(t, err.Error(), "failed to auto-migrate models")
		assert.Contains(t, err.Error(), "unsupported data type")
	})
}

func TestProvideDatabase_ModelOptions(t *testing.T) {
	t.Run("empty models option", func(t *testing.T) {
		cfg := createTestConfig("sqlite", ":memory:", true)
		logger := newTestLogger()
		modelsOpt := WithModels()

		db, err := ProvideDatabase(cfg, modelsOpt, logger)

		assert.NoError(t, err)
		assert.NotNil(t, db)

		sqlDB, err := db.DB()
		require.NoError(t, err)
		defer sqlDB.Close()
	})

	t.Run("multiple models with auto-migration", func(t *testing.T) {
		type SecondModel struct {
			ID    uint `gorm:"primaryKey"`
			Value string
		}

		cfg := createTestConfig("sqlite", ":memory:", true)
		logger := newTestLogger()
		modelsOpt := WithModels(TestModel{}, SecondModel{})

		db, err := ProvideDatabase(cfg, modelsOpt, logger)

		assert.NoError(t, err)
		assert.NotNil(t, db)

		assert.True(t, db.Migrator().HasTable(&TestModel{}))
		assert.True(t, db.Migrator().HasTable(&SecondModel{}))

		sqlDB, err := db.DB()
		require.NoError(t, err)
		defer sqlDB.Close()
	})
}

func TestProvideDatabase_Performance(t *testing.T) {
	t.Run("connection timing", func(t *testing.T) {
		cfg := createTestConfig("sqlite", ":memory:", false)
		logger := newTestLogger()

		start := time.Now()
		db, err := ProvideDatabase(cfg, nil, logger)
		duration := time.Since(start)

		assert.NoError(t, err)
		assert.NotNil(t, db)
		assert.Less(t, duration, 5*time.Second, "Database connection should be fast")

		sqlDB, err := db.DB()
		require.NoError(t, err)
		defer sqlDB.Close()
	})
}
