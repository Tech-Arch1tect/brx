package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

func TestModule(t *testing.T) {
	t.Run("module is properly defined", func(t *testing.T) {
		assert.NotNil(t, Module)
	})

	t.Run("module contains provider function", func(t *testing.T) {
		app := fx.New(
			Module,
			fx.Provide(func() *config.Config {
				cfg := createTestConfig("sqlite", ":memory:", false)
				return &cfg
			}),
			fx.Provide(func() *logging.Service {
				return newTestLogger()
			}),
			fx.Provide(func() *ModelsOption {
				return nil
			}),
			fx.NopLogger,
			fx.Invoke(func(db *gorm.DB) {
				assert.NotNil(t, db)
			}),
		)

		assert.NoError(t, app.Err())
	})
}

func TestProvideDatabaseFx(t *testing.T) {
	t.Run("successful database provision through fx", func(t *testing.T) {
		cfg := createTestConfig("sqlite", ":memory:", false)
		logger := newTestLogger()
		modelsOpt := (*ModelsOption)(nil)

		db, err := ProvideDatabaseFx(&cfg, modelsOpt, logger)

		assert.NoError(t, err)
		assert.NotNil(t, db)

		sqlDB, dbErr := db.DB()
		assert.NoError(t, dbErr)
		assert.NoError(t, sqlDB.Ping())
		defer sqlDB.Close()
	})

	t.Run("error case through fx", func(t *testing.T) {
		cfg := createTestConfig("unsupported", "test", false)
		logger := newTestLogger()
		modelsOpt := (*ModelsOption)(nil)

		db, err := ProvideDatabaseFx(&cfg, modelsOpt, logger)

		assert.Error(t, err)
		assert.Nil(t, db)
		assert.Contains(t, err.Error(), "unsupported database driver")
	})

	t.Run("with models through fx", func(t *testing.T) {
		cfg := createTestConfig("sqlite", ":memory:", true)
		logger := newTestLogger()
		modelsOpt := WithModels(TestModel{})

		db, err := ProvideDatabaseFx(&cfg, modelsOpt, logger)

		assert.NoError(t, err)
		assert.NotNil(t, db)
		assert.True(t, db.Migrator().HasTable(&TestModel{}))

		sqlDB, dbErr := db.DB()
		assert.NoError(t, dbErr)
		defer sqlDB.Close()
	})

	t.Run("without logger through fx", func(t *testing.T) {
		cfg := createTestConfig("sqlite", ":memory:", false)
		modelsOpt := (*ModelsOption)(nil)

		db, err := ProvideDatabaseFx(&cfg, modelsOpt, nil)

		assert.NoError(t, err)
		assert.NotNil(t, db)

		sqlDB, dbErr := db.DB()
		assert.NoError(t, dbErr)
		defer sqlDB.Close()
	})
}
