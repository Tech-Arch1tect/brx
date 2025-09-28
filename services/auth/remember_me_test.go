package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/testutils"
)

func TestService_CreateRememberMeToken(t *testing.T) {
	db := testutils.SetupTestDB(t, &RememberMeToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.RememberMeEnabled = true
	service := NewService(cfg, db, nil)

	testUserID := uint(1)

	t.Run("creates valid remember me token", func(t *testing.T) {
		token, err := service.CreateRememberMeToken(testUserID)

		require.NoError(t, err)
		require.NotNil(t, token)
		assert.Equal(t, testUserID, token.UserID)
		assert.NotEmpty(t, token.Token)
		assert.False(t, token.Used)
		assert.Nil(t, token.UsedAt)
		assert.True(t, token.ExpiresAt.After(time.Now()))

		expectedExpiry := token.CreatedAt.Add(cfg.Auth.RememberMeExpiry)
		assert.WithinDuration(t, expectedExpiry, token.ExpiresAt, time.Second)
	})

	t.Run("fails when remember me disabled", func(t *testing.T) {
		cfgDisabled := testutils.GetTestConfig()
		cfgDisabled.Auth.RememberMeEnabled = false
		serviceDisabled := NewService(cfgDisabled, db, nil)

		token, err := serviceDisabled.CreateRememberMeToken(testUserID)

		require.Error(t, err)
		assert.Nil(t, token)
		testutils.AssertErrorType(t, ErrRememberMeDisabled, err)
	})

	t.Run("fails when database is nil", func(t *testing.T) {
		serviceNoDB := NewService(cfg, nil, nil)

		token, err := serviceNoDB.CreateRememberMeToken(testUserID)

		require.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "database is required")
	})

	t.Run("invalidates previous tokens when creating new token", func(t *testing.T) {

		token1, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		token2, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		assert.NotEqual(t, token1.Token, token2.Token)

		var count int64
		db.Model(&RememberMeToken{}).Where("token = ?", token1.Token).Count(&count)
		assert.Equal(t, int64(0), count)

		db.Model(&RememberMeToken{}).Where("token = ?", token2.Token).Count(&count)
		assert.Equal(t, int64(1), count)
	})

	t.Run("tokens are stored in database", func(t *testing.T) {
		token, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		var dbToken RememberMeToken
		err = db.Where("token = ?", token.Token).First(&dbToken).Error
		require.NoError(t, err)

		assert.Equal(t, token.UserID, dbToken.UserID)
		assert.Equal(t, token.Token, dbToken.Token)
		assert.Equal(t, token.Used, dbToken.Used)
		assert.WithinDuration(t, token.ExpiresAt, dbToken.ExpiresAt, time.Second)
	})
}

func TestService_ValidateRememberMeToken(t *testing.T) {
	db := testutils.SetupTestDB(t, &RememberMeToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.RememberMeEnabled = true
	service := NewService(cfg, db, nil)

	testUserID := uint(1)

	t.Run("validates valid token", func(t *testing.T) {
		createdToken, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		validatedToken, err := service.ValidateRememberMeToken(createdToken.Token)

		require.NoError(t, err)
		require.NotNil(t, validatedToken)
		assert.Equal(t, createdToken.UserID, validatedToken.UserID)
		assert.Equal(t, createdToken.Token, validatedToken.Token)
		assert.False(t, validatedToken.Used)
	})

	t.Run("fails for non-existent token", func(t *testing.T) {
		token, err := service.ValidateRememberMeToken("non-existent-token")

		require.Error(t, err)
		assert.Nil(t, token)
		testutils.AssertErrorType(t, ErrRememberMeTokenInvalid, err)
	})

	t.Run("fails for expired token", func(t *testing.T) {

		createdToken, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		expiredTime := time.Now().Add(-time.Hour)
		db.Model(&RememberMeToken{}).Where("id = ?", createdToken.ID).Update("expires_at", expiredTime)

		token, err := service.ValidateRememberMeToken(createdToken.Token)

		require.Error(t, err)
		assert.Nil(t, token)
		testutils.AssertErrorType(t, ErrRememberMeTokenExpired, err)
	})

	t.Run("fails for used token", func(t *testing.T) {

		createdToken, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		_, err = service.UseRememberMeToken(createdToken.Token)
		require.NoError(t, err)

		token, err := service.ValidateRememberMeToken(createdToken.Token)

		require.Error(t, err)
		assert.Nil(t, token)
		testutils.AssertErrorType(t, ErrRememberMeTokenUsed, err)
	})

	t.Run("fails when remember me disabled", func(t *testing.T) {
		cfgDisabled := testutils.GetTestConfig()
		cfgDisabled.Auth.RememberMeEnabled = false
		serviceDisabled := NewService(cfgDisabled, db, nil)

		token, err := serviceDisabled.ValidateRememberMeToken("any-token")

		require.Error(t, err)
		assert.Nil(t, token)
		testutils.AssertErrorType(t, ErrRememberMeDisabled, err)
	})

	t.Run("fails when database is nil", func(t *testing.T) {
		serviceNoDB := NewService(cfg, nil, nil)

		token, err := serviceNoDB.ValidateRememberMeToken("any-token")

		require.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "database is required")
	})
}

func TestService_UseRememberMeToken(t *testing.T) {
	db := testutils.SetupTestDB(t, &RememberMeToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.RememberMeEnabled = true
	service := NewService(cfg, db, nil)

	testUserID := uint(1)

	t.Run("marks token as used", func(t *testing.T) {
		createdToken, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		usedToken, err := service.UseRememberMeToken(createdToken.Token)

		require.NoError(t, err)
		require.NotNil(t, usedToken)
		assert.Equal(t, createdToken.UserID, usedToken.UserID)
		assert.Equal(t, createdToken.Token, usedToken.Token)
		assert.True(t, usedToken.Used)
		assert.NotNil(t, usedToken.UsedAt)
		assert.True(t, usedToken.UsedAt.After(createdToken.CreatedAt))
	})

	t.Run("fails for already used token", func(t *testing.T) {
		createdToken, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		_, err = service.UseRememberMeToken(createdToken.Token)
		require.NoError(t, err)

		token, err := service.UseRememberMeToken(createdToken.Token)

		require.Error(t, err)
		assert.Nil(t, token)
		testutils.AssertErrorType(t, ErrRememberMeTokenUsed, err)
	})

	t.Run("fails for non-existent token", func(t *testing.T) {
		token, err := service.UseRememberMeToken("non-existent-token")

		require.Error(t, err)
		assert.Nil(t, token)
		testutils.AssertErrorType(t, ErrRememberMeTokenInvalid, err)
	})

	t.Run("fails for expired token", func(t *testing.T) {

		createdToken, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		expiredTime := time.Now().Add(-time.Hour)
		db.Model(&RememberMeToken{}).Where("id = ?", createdToken.ID).Update("expires_at", expiredTime)

		token, err := service.UseRememberMeToken(createdToken.Token)

		require.Error(t, err)
		assert.Nil(t, token)
		testutils.AssertErrorType(t, ErrRememberMeTokenExpired, err)
	})
}

func TestService_CleanupExpiredRememberMeTokens(t *testing.T) {
	db := testutils.SetupTestDB(t, &RememberMeToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.RememberMeEnabled = true
	service := NewService(cfg, db, nil)

	testUserID := uint(1)

	t.Run("removes expired tokens", func(t *testing.T) {

		validToken, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		expiredToken := &RememberMeToken{
			UserID:    testUserID + 1,
			Token:     "expired-token",
			ExpiresAt: time.Now().Add(-time.Hour),
			Used:      false,
		}
		db.Create(expiredToken)

		err = service.CleanupExpiredRememberMeTokens()
		require.NoError(t, err)

		var expiredCount int64
		db.Model(&RememberMeToken{}).Where("token = ?", expiredToken.Token).Count(&expiredCount)
		assert.Equal(t, int64(0), expiredCount)

		var validCount int64
		db.Model(&RememberMeToken{}).Where("token = ?", validToken.Token).Count(&validCount)
		assert.Equal(t, int64(1), validCount)
	})

	t.Run("fails when remember me disabled", func(t *testing.T) {
		cfgDisabled := testutils.GetTestConfig()
		cfgDisabled.Auth.RememberMeEnabled = false
		serviceDisabled := NewService(cfgDisabled, db, nil)

		err := serviceDisabled.CleanupExpiredRememberMeTokens()

		require.Error(t, err)
		testutils.AssertErrorType(t, ErrRememberMeDisabled, err)
	})

	t.Run("fails when database is nil", func(t *testing.T) {
		serviceNoDB := NewService(cfg, nil, nil)

		err := serviceNoDB.CleanupExpiredRememberMeTokens()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "database is required")
	})
}

func TestService_IsRememberMeEnabled(t *testing.T) {
	t.Run("returns true when remember me enabled", func(t *testing.T) {
		cfg := testutils.GetTestConfig()
		cfg.Auth.RememberMeEnabled = true
		service := NewService(cfg, nil, nil)

		enabled := service.IsRememberMeEnabled()

		assert.True(t, enabled)
	})

	t.Run("returns false when remember me disabled", func(t *testing.T) {
		cfg := testutils.GetTestConfig()
		cfg.Auth.RememberMeEnabled = false
		service := NewService(cfg, nil, nil)

		enabled := service.IsRememberMeEnabled()

		assert.False(t, enabled)
	})
}

func TestService_InvalidateRememberMeTokens(t *testing.T) {
	db := testutils.SetupTestDB(t, &RememberMeToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.RememberMeEnabled = true
	service := NewService(cfg, db, nil)

	testUserID := uint(1)
	otherUserID := uint(2)

	t.Run("invalidates all tokens for user", func(t *testing.T) {

		_, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		_, err = service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		otherToken, err := service.CreateRememberMeToken(otherUserID)
		require.NoError(t, err)

		err = service.InvalidateRememberMeTokens(testUserID)
		require.NoError(t, err)

		var testUserCount int64
		db.Model(&RememberMeToken{}).Where("user_id = ?", testUserID).Count(&testUserCount)
		assert.Equal(t, int64(0), testUserCount)

		var otherUserCount int64
		db.Model(&RememberMeToken{}).Where("token = ?", otherToken.Token).Count(&otherUserCount)
		assert.Equal(t, int64(1), otherUserCount)
	})

	t.Run("fails when remember me disabled", func(t *testing.T) {
		cfgDisabled := testutils.GetTestConfig()
		cfgDisabled.Auth.RememberMeEnabled = false
		serviceDisabled := NewService(cfgDisabled, db, nil)

		err := serviceDisabled.InvalidateRememberMeTokens(testUserID)

		require.Error(t, err)
		testutils.AssertErrorType(t, ErrRememberMeDisabled, err)
	})

	t.Run("fails when database is nil", func(t *testing.T) {
		serviceNoDB := NewService(cfg, nil, nil)

		err := serviceNoDB.InvalidateRememberMeTokens(testUserID)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "database is required")
	})
}

func TestService_GetRememberMeExpiry(t *testing.T) {
	cfg := testutils.GetTestConfig()
	expectedExpiry := 24 * time.Hour
	cfg.Auth.RememberMeExpiry = expectedExpiry
	service := NewService(cfg, nil, nil)

	expiry := service.GetRememberMeExpiry()

	assert.Equal(t, expectedExpiry, expiry)
}

func TestService_GetRememberMeCookieSecure(t *testing.T) {
	t.Run("returns configured value", func(t *testing.T) {
		cfg := testutils.GetTestConfig()
		cfg.Auth.RememberMeCookieSecure = true
		service := NewService(cfg, nil, nil)

		secure := service.GetRememberMeCookieSecure()

		assert.True(t, secure)
	})

	t.Run("returns false when disabled", func(t *testing.T) {
		cfg := testutils.GetTestConfig()
		cfg.Auth.RememberMeCookieSecure = false
		service := NewService(cfg, nil, nil)

		secure := service.GetRememberMeCookieSecure()

		assert.False(t, secure)
	})
}

func TestService_GetRememberMeCookieSameSite(t *testing.T) {
	cfg := testutils.GetTestConfig()
	expectedSameSite := "strict"
	cfg.Auth.RememberMeCookieSameSite = expectedSameSite
	service := NewService(cfg, nil, nil)

	sameSite := service.GetRememberMeCookieSameSite()

	assert.Equal(t, expectedSameSite, sameSite)
}

func TestService_ShouldRotateRememberMeToken(t *testing.T) {
	t.Run("returns true when rotation enabled", func(t *testing.T) {
		cfg := testutils.GetTestConfig()
		cfg.Auth.RememberMeRotateOnUse = true
		service := NewService(cfg, nil, nil)

		shouldRotate := service.ShouldRotateRememberMeToken()

		assert.True(t, shouldRotate)
	})

	t.Run("returns false when rotation disabled", func(t *testing.T) {
		cfg := testutils.GetTestConfig()
		cfg.Auth.RememberMeRotateOnUse = false
		service := NewService(cfg, nil, nil)

		shouldRotate := service.ShouldRotateRememberMeToken()

		assert.False(t, shouldRotate)
	})
}

func TestService_RotateRememberMeToken(t *testing.T) {
	db := testutils.SetupTestDB(t, &RememberMeToken{})
	defer testutils.CleanupTestDB(t, db)

	cfg := testutils.GetTestConfig()
	cfg.Auth.RememberMeEnabled = true
	service := NewService(cfg, db, nil)

	testUserID := uint(1)

	t.Run("creates new token and removes old one", func(t *testing.T) {

		oldToken, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		newToken, err := service.RotateRememberMeToken(oldToken.Token)

		require.NoError(t, err)
		require.NotNil(t, newToken)
		assert.Equal(t, oldToken.UserID, newToken.UserID)
		assert.NotEqual(t, oldToken.Token, newToken.Token)
		assert.False(t, newToken.Used)
		assert.Nil(t, newToken.UsedAt)

		var oldCount int64
		db.Model(&RememberMeToken{}).Where("token = ?", oldToken.Token).Count(&oldCount)
		assert.Equal(t, int64(0), oldCount)

		var newCount int64
		db.Model(&RememberMeToken{}).Where("token = ?", newToken.Token).Count(&newCount)
		assert.Equal(t, int64(1), newCount)
	})

	t.Run("fails when remember me disabled", func(t *testing.T) {
		cfgDisabled := testutils.GetTestConfig()
		cfgDisabled.Auth.RememberMeEnabled = false
		serviceDisabled := NewService(cfgDisabled, db, nil)

		token, err := serviceDisabled.RotateRememberMeToken("any-token")

		require.Error(t, err)
		assert.Nil(t, token)
		testutils.AssertErrorType(t, ErrRememberMeDisabled, err)
	})

	t.Run("fails for invalid token", func(t *testing.T) {
		token, err := service.RotateRememberMeToken("invalid-token")

		require.Error(t, err)
		assert.Nil(t, token)
		testutils.AssertErrorType(t, ErrRememberMeTokenInvalid, err)
	})

	t.Run("fails for expired token", func(t *testing.T) {

		createdToken, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		expiredTime := time.Now().Add(-time.Hour)
		db.Model(&RememberMeToken{}).Where("id = ?", createdToken.ID).Update("expires_at", expiredTime)

		token, err := service.RotateRememberMeToken(createdToken.Token)

		require.Error(t, err)
		assert.Nil(t, token)
		testutils.AssertErrorType(t, ErrRememberMeTokenExpired, err)
	})

	t.Run("fails for used token", func(t *testing.T) {

		createdToken, err := service.CreateRememberMeToken(testUserID)
		require.NoError(t, err)

		_, err = service.UseRememberMeToken(createdToken.Token)
		require.NoError(t, err)

		token, err := service.RotateRememberMeToken(createdToken.Token)

		require.Error(t, err)
		assert.Nil(t, token)
		testutils.AssertErrorType(t, ErrRememberMeTokenUsed, err)
	})
}
