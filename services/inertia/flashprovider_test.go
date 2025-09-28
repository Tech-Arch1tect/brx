package inertia

import (
	"context"
	"testing"

	gonertia "github.com/romsar/gonertia/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSCSFlashProvider(t *testing.T) {
	provider := NewSCSFlashProvider()
	assert.NotNil(t, provider)
	assert.IsType(t, &SCSFlashProvider{}, provider)
}

func TestSCSFlashProvider_FlashErrors(t *testing.T) {
	provider := NewSCSFlashProvider()
	errors := gonertia.ValidationErrors{
		"email": []string{"The email field is required"},
		"name":  []string{"The name field is required", "The name must be at least 3 characters"},
	}

	t.Run("without session manager in context", func(t *testing.T) {
		ctx := context.Background()

		err := provider.FlashErrors(ctx, errors)
		require.NoError(t, err)
	})
}

func TestSCSFlashProvider_GetErrors(t *testing.T) {
	provider := NewSCSFlashProvider()

	t.Run("without session manager in context", func(t *testing.T) {
		ctx := context.Background()

		errors, err := provider.GetErrors(ctx)
		require.NoError(t, err)
		assert.Nil(t, errors)
	})
}

func TestSCSFlashProvider_FlashClearHistory(t *testing.T) {
	provider := NewSCSFlashProvider()

	t.Run("without session manager in context", func(t *testing.T) {
		ctx := context.Background()

		err := provider.FlashClearHistory(ctx)
		require.NoError(t, err)
	})
}

func TestSCSFlashProvider_ShouldClearHistory(t *testing.T) {
	provider := NewSCSFlashProvider()

	t.Run("without session manager in context", func(t *testing.T) {
		ctx := context.Background()

		shouldClear, err := provider.ShouldClearHistory(ctx)
		require.NoError(t, err)
		assert.False(t, shouldClear)
	})
}
