package refreshtoken

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/testutils"
)

type mockJWTService struct {
	generateTokenFunc func(userID uint) (string, error)
	extractJTIFunc    func(tokenString string) (string, error)
}

func (m *mockJWTService) GenerateToken(userID uint) (string, error) {
	if m.generateTokenFunc != nil {
		return m.generateTokenFunc(userID)
	}
	return "mock-jwt-token", nil
}

func (m *mockJWTService) ExtractJTI(tokenString string) (string, error) {
	if m.extractJTIFunc != nil {
		return m.extractJTIFunc(tokenString)
	}
	return "mock-jti", nil
}

func getTestRefreshTokenConfig() *config.Config {
	return &config.Config{
		RefreshToken: config.RefreshTokenConfig{
			TokenLength:     32,
			Expiry:          24 * time.Hour,
			RotationMode:    "always",
			CleanupInterval: 1 * time.Hour,
		},
	}
}

func TestNewService(t *testing.T) {
	cfg := getTestRefreshTokenConfig()
	db := testutils.SetupTestDB(t, &RefreshToken{})

	service := NewService(db, cfg, nil)

	assert.NotNil(t, service)
	assert.Equal(t, db, service.db)
	assert.Equal(t, cfg, service.config)
	assert.Nil(t, service.logger)
}

func TestService_GenerateRefreshToken(t *testing.T) {
	cfg := getTestRefreshTokenConfig()
	db := testutils.SetupTestDB(t, &RefreshToken{})
	service := NewService(db, cfg, nil)

	t.Run("valid token generation", func(t *testing.T) {
		userID := uint(123)
		sessionInfo := TokenSessionInfo{
			IPAddress: "192.168.1.1",
			UserAgent: "test-agent",
			DeviceInfo: map[string]any{
				"os":      "linux",
				"browser": "firefox",
			},
		}

		tokenData, err := service.GenerateRefreshToken(userID, sessionInfo)

		require.NoError(t, err)
		assert.NotNil(t, tokenData)
		assert.NotEmpty(t, tokenData.Token)
		assert.NotEmpty(t, tokenData.Hash)
		assert.NotZero(t, tokenData.TokenID)
		assert.True(t, tokenData.ExpiresAt.After(time.Now()))

		var storedToken RefreshToken
		err = db.Where("id = ?", tokenData.TokenID).First(&storedToken).Error
		require.NoError(t, err)
		assert.Equal(t, userID, storedToken.UserID)
		assert.Equal(t, tokenData.Hash, storedToken.TokenHash)
		assert.NotEmpty(t, storedToken.DeviceInfo)
	})

	t.Run("token generation without device info", func(t *testing.T) {
		userID := uint(456)
		sessionInfo := TokenSessionInfo{}

		tokenData, err := service.GenerateRefreshToken(userID, sessionInfo)

		require.NoError(t, err)
		assert.NotNil(t, tokenData)
		assert.NotEmpty(t, tokenData.Token)

		var storedToken RefreshToken
		err = db.Where("id = ?", tokenData.TokenID).First(&storedToken).Error
		require.NoError(t, err)
		assert.Equal(t, userID, storedToken.UserID)
		assert.Empty(t, storedToken.DeviceInfo)
	})
}

func TestService_ValidateRefreshToken(t *testing.T) {
	cfg := getTestRefreshTokenConfig()
	db := testutils.SetupTestDB(t, &RefreshToken{})
	service := NewService(db, cfg, nil)

	t.Run("valid token", func(t *testing.T) {
		userID := uint(123)
		sessionInfo := TokenSessionInfo{}

		tokenData, err := service.GenerateRefreshToken(userID, sessionInfo)
		require.NoError(t, err)

		refreshToken, err := service.ValidateRefreshToken(tokenData.Token)

		require.NoError(t, err)
		assert.NotNil(t, refreshToken)
		assert.Equal(t, userID, refreshToken.UserID)
		assert.Equal(t, tokenData.TokenID, refreshToken.ID)
	})

	t.Run("token not found", func(t *testing.T) {
		invalidToken := "invalid-token-string"

		refreshToken, err := service.ValidateRefreshToken(invalidToken)

		require.Error(t, err)
		assert.Nil(t, refreshToken)
		testutils.AssertErrorType(t, ErrRefreshTokenNotFound, err)
	})

	t.Run("expired token", func(t *testing.T) {
		userID := uint(789)
		pastTime := time.Now().Add(-1 * time.Hour)
		tokenString := "expired-token"
		tokenHash := service.hashToken(tokenString)

		expiredToken := RefreshToken{
			UserID:    userID,
			TokenHash: tokenHash,
			ExpiresAt: pastTime,
			CreatedAt: time.Now(),
			LastUsed:  time.Now(),
		}
		err := db.Create(&expiredToken).Error
		require.NoError(t, err)

		refreshToken, err := service.ValidateRefreshToken(tokenString)

		require.Error(t, err)
		assert.Nil(t, refreshToken)
		testutils.AssertErrorType(t, ErrRefreshTokenExpired, err)

		var deletedToken RefreshToken
		err = db.Where("id = ?", expiredToken.ID).First(&deletedToken).Error
		assert.Error(t, err)
	})
}

func TestService_ValidateAndRotateRefreshToken(t *testing.T) {
	cfg := getTestRefreshTokenConfig()
	db := testutils.SetupTestDB(t, &RefreshToken{})
	service := NewService(db, cfg, nil)
	mockJWT := &mockJWTService{}

	t.Run("successful rotation", func(t *testing.T) {
		userID := uint(123)
		sessionInfo := TokenSessionInfo{
			DeviceInfo: map[string]any{"browser": "chrome"},
		}

		originalTokenData, err := service.GenerateRefreshToken(userID, sessionInfo)
		require.NoError(t, err)

		mockJWT.generateTokenFunc = func(uid uint) (string, error) {
			assert.Equal(t, userID, uid)
			return "new-access-token", nil
		}

		result, err := service.ValidateAndRotateRefreshToken(originalTokenData.Token, mockJWT)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "new-access-token", result.AccessToken)
		assert.NotEmpty(t, result.RefreshToken)
		assert.NotEqual(t, originalTokenData.Token, result.RefreshToken)
		assert.NotZero(t, result.RefreshTokenID)
		assert.Equal(t, originalTokenData.TokenID, result.OldTokenID)
		assert.True(t, result.OldTokenRevoked)
		assert.True(t, result.ExpiresAt.After(time.Now()))

		var oldToken RefreshToken
		err = db.Where("id = ?", originalTokenData.TokenID).First(&oldToken).Error
		assert.Error(t, err)

		newToken, err := service.ValidateRefreshToken(result.RefreshToken)
		require.NoError(t, err)
		assert.Equal(t, userID, newToken.UserID)
		assert.Equal(t, result.RefreshTokenID, newToken.ID)
	})

	t.Run("invalid token for rotation", func(t *testing.T) {
		invalidToken := "invalid-token"

		result, err := service.ValidateAndRotateRefreshToken(invalidToken, mockJWT)

		require.Error(t, err)
		assert.Nil(t, result)
		testutils.AssertErrorType(t, ErrRefreshTokenNotFound, err)
	})

	t.Run("JWT generation failure", func(t *testing.T) {
		userID := uint(456)
		sessionInfo := TokenSessionInfo{}

		tokenData, err := service.GenerateRefreshToken(userID, sessionInfo)
		require.NoError(t, err)

		mockJWT.generateTokenFunc = func(uid uint) (string, error) {
			return "", assert.AnError
		}

		result, err := service.ValidateAndRotateRefreshToken(tokenData.Token, mockJWT)

		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to generate new access token")
	})
}

func TestService_RevokeRefreshToken(t *testing.T) {
	cfg := getTestRefreshTokenConfig()
	db := testutils.SetupTestDB(t, &RefreshToken{})
	service := NewService(db, cfg, nil)

	t.Run("successful revocation", func(t *testing.T) {
		userID := uint(123)
		sessionInfo := TokenSessionInfo{}

		tokenData, err := service.GenerateRefreshToken(userID, sessionInfo)
		require.NoError(t, err)

		err = service.RevokeRefreshToken(tokenData.Token)

		assert.NoError(t, err)

		var revokedToken RefreshToken
		err = db.Where("id = ?", tokenData.TokenID).First(&revokedToken).Error
		assert.Error(t, err)
	})

	t.Run("revoke non-existent token", func(t *testing.T) {
		err := service.RevokeRefreshToken("non-existent-token")

		assert.NoError(t, err)
	})
}

func TestService_RevokeRefreshTokenByID(t *testing.T) {
	cfg := getTestRefreshTokenConfig()
	db := testutils.SetupTestDB(t, &RefreshToken{})
	service := NewService(db, cfg, nil)

	t.Run("successful revocation by ID", func(t *testing.T) {
		userID := uint(123)
		sessionInfo := TokenSessionInfo{}

		tokenData, err := service.GenerateRefreshToken(userID, sessionInfo)
		require.NoError(t, err)

		err = service.RevokeRefreshTokenByID(tokenData.TokenID)

		assert.NoError(t, err)

		var revokedToken RefreshToken
		err = db.Where("id = ?", tokenData.TokenID).First(&revokedToken).Error
		assert.Error(t, err)
	})

	t.Run("revoke non-existent token by ID", func(t *testing.T) {
		err := service.RevokeRefreshTokenByID(999999)

		assert.NoError(t, err)
	})
}

func TestService_RevokeAllUserRefreshTokens(t *testing.T) {
	cfg := getTestRefreshTokenConfig()
	db := testutils.SetupTestDB(t, &RefreshToken{})
	service := NewService(db, cfg, nil)

	userID := uint(123)
	sessionInfo := TokenSessionInfo{}

	tokenData1, err := service.GenerateRefreshToken(userID, sessionInfo)
	require.NoError(t, err)

	tokenData2, err := service.GenerateRefreshToken(userID, sessionInfo)
	require.NoError(t, err)

	otherUserID := uint(456)
	tokenData3, err := service.GenerateRefreshToken(otherUserID, sessionInfo)
	require.NoError(t, err)

	err = service.RevokeAllUserRefreshTokens(userID)

	assert.NoError(t, err)

	var token1, token2, token3 RefreshToken
	err = db.Where("id = ?", tokenData1.TokenID).First(&token1).Error
	assert.Error(t, err)

	err = db.Where("id = ?", tokenData2.TokenID).First(&token2).Error
	assert.Error(t, err)

	err = db.Where("id = ?", tokenData3.TokenID).First(&token3).Error
	assert.NoError(t, err)
	assert.Equal(t, otherUserID, token3.UserID)
}

func TestService_GetRefreshTokenByHash(t *testing.T) {
	cfg := getTestRefreshTokenConfig()
	db := testutils.SetupTestDB(t, &RefreshToken{})
	service := NewService(db, cfg, nil)

	t.Run("token found", func(t *testing.T) {
		userID := uint(123)
		sessionInfo := TokenSessionInfo{}

		tokenData, err := service.GenerateRefreshToken(userID, sessionInfo)
		require.NoError(t, err)

		refreshToken, err := service.GetRefreshTokenByHash(tokenData.Hash)

		require.NoError(t, err)
		assert.NotNil(t, refreshToken)
		assert.Equal(t, userID, refreshToken.UserID)
		assert.Equal(t, tokenData.TokenID, refreshToken.ID)
	})

	t.Run("token not found", func(t *testing.T) {
		refreshToken, err := service.GetRefreshTokenByHash("non-existent-hash")

		require.Error(t, err)
		assert.Nil(t, refreshToken)
		testutils.AssertErrorType(t, ErrRefreshTokenNotFound, err)
	})
}

func TestService_UpdateLastUsed(t *testing.T) {
	cfg := getTestRefreshTokenConfig()
	db := testutils.SetupTestDB(t, &RefreshToken{})
	service := NewService(db, cfg, nil)

	userID := uint(123)
	sessionInfo := TokenSessionInfo{}

	tokenData, err := service.GenerateRefreshToken(userID, sessionInfo)
	require.NoError(t, err)

	originalLastUsed := time.Now().Add(-1 * time.Hour)
	err = db.Model(&RefreshToken{}).
		Where("id = ?", tokenData.TokenID).
		Update("last_used", originalLastUsed).Error
	require.NoError(t, err)

	err = service.UpdateLastUsed(tokenData.TokenID)

	assert.NoError(t, err)

	var updatedToken RefreshToken
	err = db.Where("id = ?", tokenData.TokenID).First(&updatedToken).Error
	require.NoError(t, err)
	assert.True(t, updatedToken.LastUsed.After(originalLastUsed))
}

func TestService_CleanupExpiredTokens(t *testing.T) {
	cfg := getTestRefreshTokenConfig()
	db := testutils.SetupTestDB(t, &RefreshToken{})
	service := NewService(db, cfg, nil)

	userID := uint(123)
	pastTime := time.Now().Add(-25 * time.Hour)

	expiredToken := RefreshToken{
		UserID:    userID,
		TokenHash: "expired-hash",
		ExpiresAt: pastTime,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}
	err := db.Create(&expiredToken).Error
	require.NoError(t, err)

	validTokenData, err := service.GenerateRefreshToken(userID, TokenSessionInfo{})
	require.NoError(t, err)

	err = service.CleanupExpiredTokens()

	assert.NoError(t, err)

	var deletedToken RefreshToken
	err = db.Where("id = ?", expiredToken.ID).First(&deletedToken).Error
	assert.Error(t, err)

	var validToken RefreshToken
	err = db.Where("id = ?", validTokenData.TokenID).First(&validToken).Error
	assert.NoError(t, err)
}

func TestService_generateSecureToken(t *testing.T) {
	cfg := getTestRefreshTokenConfig()
	service := NewService(nil, cfg, nil)

	token1, err1 := service.generateSecureToken()
	token2, err2 := service.generateSecureToken()

	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.NotEmpty(t, token1)
	assert.NotEmpty(t, token2)
	assert.NotEqual(t, token1, token2)

	expectedLength := (cfg.RefreshToken.TokenLength*8 + 5) / 6
	assert.Equal(t, expectedLength, len(token1))
	assert.Equal(t, expectedLength, len(token2))
}

func TestService_hashToken(t *testing.T) {
	service := NewService(nil, getTestRefreshTokenConfig(), nil)

	token := "test-token-string"
	hash1 := service.hashToken(token)
	hash2 := service.hashToken(token)

	assert.Equal(t, hash1, hash2)
	assert.NotEmpty(t, hash1)
	assert.Equal(t, 64, len(hash1))

	differentHash := service.hashToken("different-token")
	assert.NotEqual(t, hash1, differentHash)
}
