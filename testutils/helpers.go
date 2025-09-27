package testutils

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func SetupTestDB(t *testing.T, models ...interface{}) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)

	if len(models) > 0 {
		err = db.AutoMigrate(models...)
		require.NoError(t, err)
	}

	return db
}

func CleanupTestDB(t *testing.T, db *gorm.DB, tables ...string) {
	if len(tables) > 0 {
		for _, table := range tables {
			err := db.Exec("DELETE FROM " + table).Error
			require.NoError(t, err)
		}
	}
}

func AssertErrorType(t *testing.T, expected error, actual error) {
	require.Error(t, actual)
	require.Equal(t, expected.Error(), actual.Error())
}

func CreateTestServer() {
	// TODO: Implement when needed for HTTP tests
}
