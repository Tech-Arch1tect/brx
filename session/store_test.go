package session

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMemoryStore(t *testing.T) {
	store := NewMemoryStore()

	assert.NotNil(t, store)
}

func TestNewDatabaseStore(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		db := setupTestDB(t)

		store, err := NewDatabaseStore(db)

		require.NoError(t, err)
		assert.NotNil(t, store)
	})

	t.Run("with nil database", func(t *testing.T) {
		store, err := NewDatabaseStore(nil)

		assert.Error(t, err)
		assert.Nil(t, store)
		assert.Contains(t, err.Error(), "database connection cannot be nil")
	})
}
