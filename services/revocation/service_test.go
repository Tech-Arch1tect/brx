package revocation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/testutils"
)

type mockStore struct {
	revokeTokenFunc          func(jti string, expiresAt time.Time) error
	isRevokedFunc            func(jti string) (bool, error)
	cleanupExpiredTokensFunc func() error
	revokeAllUserTokensFunc  func(userID uint, issuedBefore time.Time) error
	loadFromDatabaseFunc     func() error
	saveToDatabaseFunc       func() error
}

func (m *mockStore) RevokeToken(jti string, expiresAt time.Time) error {
	if m.revokeTokenFunc != nil {
		return m.revokeTokenFunc(jti, expiresAt)
	}
	return nil
}

func (m *mockStore) IsRevoked(jti string) (bool, error) {
	if m.isRevokedFunc != nil {
		return m.isRevokedFunc(jti)
	}
	return false, nil
}

func (m *mockStore) CleanupExpiredTokens() error {
	if m.cleanupExpiredTokensFunc != nil {
		return m.cleanupExpiredTokensFunc()
	}
	return nil
}

func (m *mockStore) RevokeAllUserTokens(userID uint, issuedBefore time.Time) error {
	if m.revokeAllUserTokensFunc != nil {
		return m.revokeAllUserTokensFunc(userID, issuedBefore)
	}
	return nil
}

func (m *mockStore) LoadFromDatabase() error {
	if m.loadFromDatabaseFunc != nil {
		return m.loadFromDatabaseFunc()
	}
	return nil
}

func (m *mockStore) SaveToDatabase() error {
	if m.saveToDatabaseFunc != nil {
		return m.saveToDatabaseFunc()
	}
	return nil
}

func getTestRevocationConfig() *config.Config {
	return &config.Config{
		Revocation: config.RevocationConfig{
			Enabled:       true,
			Store:         "memory",
			CleanupPeriod: 1 * time.Hour,
		},
	}
}

func TestNewService(t *testing.T) {
	cfg := getTestRevocationConfig()
	store := &mockStore{}

	service := NewService(cfg, store, nil)

	assert.NotNil(t, service)
	assert.Equal(t, cfg, service.config)
	assert.Equal(t, store, service.store)
	assert.Nil(t, service.logger)
}

func TestService_RevokeToken(t *testing.T) {
	cfg := getTestRevocationConfig()

	t.Run("successful revocation", func(t *testing.T) {
		store := &mockStore{}
		service := NewService(cfg, store, nil)

		jti := "test-jti-123"
		expiresAt := time.Now().Add(1 * time.Hour)

		var capturedJTI string
		var capturedExpiry time.Time
		store.revokeTokenFunc = func(j string, e time.Time) error {
			capturedJTI = j
			capturedExpiry = e
			return nil
		}

		err := service.RevokeToken(jti, expiresAt)

		assert.NoError(t, err)
		assert.Equal(t, jti, capturedJTI)
		assert.Equal(t, expiresAt, capturedExpiry)
	})

	t.Run("store error", func(t *testing.T) {
		store := &mockStore{}
		service := NewService(cfg, store, nil)

		store.revokeTokenFunc = func(j string, e time.Time) error {
			return assert.AnError
		}

		err := service.RevokeToken("test-jti", time.Now())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to revoke token by JTI")
	})

	t.Run("no store configured", func(t *testing.T) {
		service := NewService(cfg, nil, nil)

		err := service.RevokeToken("test-jti", time.Now())

		assert.Error(t, err)
		testutils.AssertErrorType(t, ErrStoreNotConfigured, err)
	})
}

func TestService_IsTokenRevoked(t *testing.T) {
	cfg := getTestRevocationConfig()

	t.Run("token is revoked", func(t *testing.T) {
		store := &mockStore{}
		service := NewService(cfg, store, nil)

		jti := "revoked-jti"
		store.isRevokedFunc = func(j string) (bool, error) {
			assert.Equal(t, jti, j)
			return true, nil
		}

		revoked, err := service.IsTokenRevoked(jti)

		assert.NoError(t, err)
		assert.True(t, revoked)
	})

	t.Run("token is not revoked", func(t *testing.T) {
		store := &mockStore{}
		service := NewService(cfg, store, nil)

		jti := "valid-jti"
		store.isRevokedFunc = func(j string) (bool, error) {
			assert.Equal(t, jti, j)
			return false, nil
		}

		revoked, err := service.IsTokenRevoked(jti)

		assert.NoError(t, err)
		assert.False(t, revoked)
	})

	t.Run("store error", func(t *testing.T) {
		store := &mockStore{}
		service := NewService(cfg, store, nil)

		store.isRevokedFunc = func(j string) (bool, error) {
			return false, assert.AnError
		}

		revoked, err := service.IsTokenRevoked("test-jti")

		assert.Error(t, err)
		assert.False(t, revoked)
		assert.Contains(t, err.Error(), "failed to check JTI revocation status")
	})

	t.Run("no store configured", func(t *testing.T) {
		service := NewService(cfg, nil, nil)

		revoked, err := service.IsTokenRevoked("test-jti")

		assert.Error(t, err)
		assert.False(t, revoked)
		testutils.AssertErrorType(t, ErrStoreNotConfigured, err)
	})
}

func TestService_RevokeAllUserTokens(t *testing.T) {
	cfg := getTestRevocationConfig()

	t.Run("successful revocation", func(t *testing.T) {
		store := &mockStore{}
		service := NewService(cfg, store, nil)

		userID := uint(123)
		issuedBefore := time.Now()

		var capturedUserID uint
		var capturedTime time.Time
		store.revokeAllUserTokensFunc = func(uid uint, before time.Time) error {
			capturedUserID = uid
			capturedTime = before
			return nil
		}

		err := service.RevokeAllUserTokens(userID, issuedBefore)

		assert.NoError(t, err)
		assert.Equal(t, userID, capturedUserID)
		assert.Equal(t, issuedBefore, capturedTime)
	})

	t.Run("store error", func(t *testing.T) {
		store := &mockStore{}
		service := NewService(cfg, store, nil)

		store.revokeAllUserTokensFunc = func(uid uint, before time.Time) error {
			return assert.AnError
		}

		err := service.RevokeAllUserTokens(123, time.Now())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to revoke all user tokens")
	})

	t.Run("no store configured", func(t *testing.T) {
		service := NewService(cfg, nil, nil)

		err := service.RevokeAllUserTokens(123, time.Now())

		assert.Error(t, err)
		testutils.AssertErrorType(t, ErrStoreNotConfigured, err)
	})
}

func TestService_CleanupExpiredTokens(t *testing.T) {
	cfg := getTestRevocationConfig()

	t.Run("successful cleanup", func(t *testing.T) {
		store := &mockStore{}
		service := NewService(cfg, store, nil)

		cleanupCalled := false
		store.cleanupExpiredTokensFunc = func() error {
			cleanupCalled = true
			return nil
		}

		err := service.CleanupExpiredTokens()

		assert.NoError(t, err)
		assert.True(t, cleanupCalled)
	})

	t.Run("store error", func(t *testing.T) {
		store := &mockStore{}
		service := NewService(cfg, store, nil)

		store.cleanupExpiredTokensFunc = func() error {
			return assert.AnError
		}

		err := service.CleanupExpiredTokens()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to cleanup expired tokens")
	})

	t.Run("no store configured", func(t *testing.T) {
		service := NewService(cfg, nil, nil)

		err := service.CleanupExpiredTokens()

		assert.Error(t, err)
		testutils.AssertErrorType(t, ErrStoreNotConfigured, err)
	})
}

func TestMemoryStore_RevokeToken(t *testing.T) {
	t.Run("revoke token in memory only", func(t *testing.T) {
		store := NewMemoryStore()
		jti := "test-jti"
		expiresAt := time.Now().Add(1 * time.Hour)

		err := store.RevokeToken(jti, expiresAt)

		assert.NoError(t, err)

		revoked, err := store.IsRevoked(jti)
		assert.NoError(t, err)
		assert.True(t, revoked)
	})

	t.Run("revoke token with database persistence", func(t *testing.T) {
		db := testutils.SetupTestDB(t, &RevokedToken{})
		store := NewMemoryStoreWithDB(db, nil)

		jti := "test-jti-db"
		expiresAt := time.Now().Add(1 * time.Hour)

		err := store.RevokeToken(jti, expiresAt)

		assert.NoError(t, err)

		var revokedToken RevokedToken
		err = db.Where("jti = ?", jti).First(&revokedToken).Error
		assert.NoError(t, err)
		assert.Equal(t, jti, revokedToken.JTI)
	})
}

func TestMemoryStore_IsRevoked(t *testing.T) {
	store := NewMemoryStore()

	t.Run("token not revoked", func(t *testing.T) {
		revoked, err := store.IsRevoked("non-existent-jti")

		assert.NoError(t, err)
		assert.False(t, revoked)
	})

	t.Run("token is revoked", func(t *testing.T) {
		jti := "revoked-jti"
		expiresAt := time.Now().Add(1 * time.Hour)

		err := store.RevokeToken(jti, expiresAt)
		require.NoError(t, err)

		revoked, err := store.IsRevoked(jti)
		assert.NoError(t, err)
		assert.True(t, revoked)
	})

	t.Run("expired token is automatically removed", func(t *testing.T) {
		jti := "expired-jti"
		expiresAt := time.Now().Add(-1 * time.Hour)

		err := store.RevokeToken(jti, expiresAt)
		require.NoError(t, err)

		revoked, err := store.IsRevoked(jti)
		assert.NoError(t, err)
		assert.False(t, revoked)
	})
}

func TestMemoryStore_CleanupExpiredTokens(t *testing.T) {
	store := NewMemoryStore()

	validJTI := "valid-jti"
	validExpiresAt := time.Now().Add(1 * time.Hour)
	err := store.RevokeToken(validJTI, validExpiresAt)
	require.NoError(t, err)

	expiredJTI := "expired-jti"
	expiredExpiresAt := time.Now().Add(-1 * time.Hour)
	err = store.RevokeToken(expiredJTI, expiredExpiresAt)
	require.NoError(t, err)

	err = store.CleanupExpiredTokens()
	assert.NoError(t, err)

	validRevoked, err := store.IsRevoked(validJTI)
	assert.NoError(t, err)
	assert.True(t, validRevoked)

	expiredRevoked, err := store.IsRevoked(expiredJTI)
	assert.NoError(t, err)
	assert.False(t, expiredRevoked)
}

func TestMemoryStore_LoadFromDatabase(t *testing.T) {
	t.Run("no database configured", func(t *testing.T) {
		store := NewMemoryStore()

		err := store.LoadFromDatabase()

		assert.NoError(t, err)
	})

	t.Run("load from database", func(t *testing.T) {
		db := testutils.SetupTestDB(t, &RevokedToken{})
		store := NewMemoryStoreWithDB(db, nil)

		jti1 := "jti-1"
		jti2 := "jti-2"
		expiredJTI := "expired-jti"

		validToken1 := RevokedToken{
			JTI:       jti1,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		validToken2 := RevokedToken{
			JTI:       jti2,
			ExpiresAt: time.Now().Add(2 * time.Hour),
		}
		expiredToken := RevokedToken{
			JTI:       expiredJTI,
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}

		err := db.Create(&validToken1).Error
		require.NoError(t, err)
		err = db.Create(&validToken2).Error
		require.NoError(t, err)
		err = db.Create(&expiredToken).Error
		require.NoError(t, err)

		err = store.LoadFromDatabase()
		assert.NoError(t, err)

		revoked1, err := store.IsRevoked(jti1)
		assert.NoError(t, err)
		assert.True(t, revoked1)

		revoked2, err := store.IsRevoked(jti2)
		assert.NoError(t, err)
		assert.True(t, revoked2)

		expiredRevoked, err := store.IsRevoked(expiredJTI)
		assert.NoError(t, err)
		assert.False(t, expiredRevoked)
	})
}

func TestMemoryStore_SaveToDatabase(t *testing.T) {
	t.Run("no database configured", func(t *testing.T) {
		store := NewMemoryStore()

		err := store.SaveToDatabase()

		assert.NoError(t, err)
	})

	t.Run("save to database", func(t *testing.T) {
		db := testutils.SetupTestDB(t, &RevokedToken{})
		store := NewMemoryStoreWithDB(db, nil)

		jti1 := "save-jti-1"
		jti2 := "save-jti-2"
		expiresAt1 := time.Now().Add(1 * time.Hour)
		expiresAt2 := time.Now().Add(2 * time.Hour)

		err := store.RevokeToken(jti1, expiresAt1)
		require.NoError(t, err)
		err = store.RevokeToken(jti2, expiresAt2)
		require.NoError(t, err)

		err = store.SaveToDatabase()
		assert.NoError(t, err)

		var tokens []RevokedToken
		err = db.Find(&tokens).Error
		assert.NoError(t, err)
		assert.Len(t, tokens, 2)

		var foundJTIs []string
		for _, token := range tokens {
			foundJTIs = append(foundJTIs, token.JTI)
		}
		assert.Contains(t, foundJTIs, jti1)
		assert.Contains(t, foundJTIs, jti2)
	})
}

func TestMemoryStore_RevokeAllUserTokens(t *testing.T) {
	store := NewMemoryStore()

	err := store.RevokeAllUserTokens(123, time.Now())

	assert.NoError(t, err)
}
