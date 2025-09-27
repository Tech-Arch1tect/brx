package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/testutils"
)

func TestNewService(t *testing.T) {
	cfg := testutils.GetTestConfig()
	service := NewService(cfg, nil)

	assert.NotNil(t, service)
	assert.Equal(t, cfg, service.config)
	assert.Nil(t, service.logger)
	assert.Nil(t, service.revocationService)
}

func TestService_SetRevocationService(t *testing.T) {
	cfg := testutils.GetTestConfig()
	service := NewService(cfg, nil)
	mockRevocation := &testutils.MockRevocationService{}

	assert.Nil(t, service.revocationService)

	service.SetRevocationService(mockRevocation)

	assert.Equal(t, mockRevocation, service.revocationService)
}

func TestService_GetAccessExpirySeconds(t *testing.T) {
	cfg := testutils.GetTestConfig()
	cfg.JWT.AccessExpiry = 15 * time.Minute
	service := NewService(cfg, nil)

	seconds := service.GetAccessExpirySeconds()

	assert.Equal(t, 900, seconds)
}

func TestService_GenerateToken(t *testing.T) {
	cfg := testutils.GetTestConfig()
	service := NewService(cfg, nil)

	t.Run("valid user ID", func(t *testing.T) {
		userID := uint(123)
		tokenString, err := service.GenerateToken(userID)

		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
			return []byte(cfg.JWT.SecretKey), nil
		})
		require.NoError(t, err)
		require.True(t, token.Valid)

		claims, ok := token.Claims.(*Claims)
		require.True(t, ok)
		assert.Equal(t, userID, claims.UserID)
		assert.NotEmpty(t, claims.JTI)
		assert.Equal(t, cfg.JWT.Issuer, claims.Issuer)
		assert.NotNil(t, claims.ExpiresAt)
		assert.NotNil(t, claims.IssuedAt)
		assert.NotNil(t, claims.NotBefore)
	})

	t.Run("zero user ID", func(t *testing.T) {
		userID := uint(0)
		tokenString, err := service.GenerateToken(userID)

		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
			return []byte(cfg.JWT.SecretKey), nil
		})
		require.NoError(t, err)

		claims, ok := token.Claims.(*Claims)
		require.True(t, ok)
		assert.Equal(t, userID, claims.UserID)
	})

	t.Run("generates unique JTI", func(t *testing.T) {
		userID := uint(123)
		token1, err1 := service.GenerateToken(userID)
		token2, err2 := service.GenerateToken(userID)

		require.NoError(t, err1)
		require.NoError(t, err2)

		claims1 := &Claims{}
		claims2 := &Claims{}

		_, err := jwt.ParseWithClaims(token1, claims1, func(token *jwt.Token) (any, error) {
			return []byte(cfg.JWT.SecretKey), nil
		})
		require.NoError(t, err)

		_, err = jwt.ParseWithClaims(token2, claims2, func(token *jwt.Token) (any, error) {
			return []byte(cfg.JWT.SecretKey), nil
		})
		require.NoError(t, err)

		assert.NotEqual(t, claims1.JTI, claims2.JTI)
	})
}

func TestService_ValidateToken(t *testing.T) {
	cfg := testutils.GetTestConfig()
	service := NewService(cfg, nil)

	t.Run("valid token", func(t *testing.T) {
		userID := uint(123)
		tokenString, err := service.GenerateToken(userID)
		require.NoError(t, err)

		claims, err := service.ValidateToken(tokenString)

		require.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, userID, claims.UserID)
		assert.NotEmpty(t, claims.JTI)
	})

	t.Run("malformed token", func(t *testing.T) {
		tokenString := "invalid.token.string"

		claims, err := service.ValidateToken(tokenString)

		require.Error(t, err)
		assert.Nil(t, claims)
		testutils.AssertErrorType(t, ErrMalformedToken, err)
	})

	t.Run("expired token", func(t *testing.T) {

		now := time.Now()
		expiredClaims := Claims{
			UserID: 123,
			JTI:    "test-jti",
			RegisteredClaims: jwt.RegisteredClaims{
				ID:        "test-jti",
				Issuer:    cfg.JWT.Issuer,
				Subject:   "123",
				ExpiresAt: jwt.NewNumericDate(now.Add(-time.Hour)),
				NotBefore: jwt.NewNumericDate(now.Add(-2 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
		tokenString, err := token.SignedString([]byte(cfg.JWT.SecretKey))
		require.NoError(t, err)

		claims, err := service.ValidateToken(tokenString)

		require.Error(t, err)
		assert.Nil(t, claims)
		testutils.AssertErrorType(t, ErrExpiredToken, err)
	})

	t.Run("invalid signature", func(t *testing.T) {
		userID := uint(123)
		tokenString, err := service.GenerateToken(userID)
		require.NoError(t, err)

		cfg.JWT.SecretKey = "different-secret-key"
		service = NewService(cfg, nil)

		claims, err := service.ValidateToken(tokenString)

		require.Error(t, err)
		assert.Nil(t, claims)
		testutils.AssertErrorType(t, ErrInvalidSignature, err)
	})

	t.Run("none algorithm rejected", func(t *testing.T) {

		claims := Claims{
			UserID: 123,
			JTI:    "test-jti",
			RegisteredClaims: jwt.RegisteredClaims{
				ID:        "test-jti",
				Issuer:    cfg.JWT.Issuer,
				Subject:   "123",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		result, err := service.ValidateToken(tokenString)

		require.Error(t, err)
		assert.Nil(t, result)

		testutils.AssertErrorType(t, ErrInvalidToken, err)
	})

	t.Run("wrong algorithm rejected", func(t *testing.T) {

		claims := Claims{
			UserID: 123,
			JTI:    "test-jti",
			RegisteredClaims: jwt.RegisteredClaims{
				ID:        "test-jti",
				Issuer:    cfg.JWT.Issuer,
				Subject:   "123",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

		_, err := token.SignedString([]byte(cfg.JWT.SecretKey))
		require.Error(t, err)

		tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsImp0aSI6InRlc3QtanRpIn0.invalid"

		result, err := service.ValidateToken(tokenString)

		require.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestService_ValidateToken_WithRevocation(t *testing.T) {
	cfg := testutils.GetTestConfig()
	service := NewService(cfg, nil)
	mockRevocation := &testutils.MockRevocationService{}
	service.SetRevocationService(mockRevocation)

	userID := uint(123)
	tokenString, err := service.GenerateToken(userID)
	require.NoError(t, err)

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		return []byte(cfg.JWT.SecretKey), nil
	})
	require.NoError(t, err)
	claims := token.Claims.(*Claims)

	t.Run("token not revoked", func(t *testing.T) {
		mockRevocation.On("IsTokenRevoked", claims.JTI).Return(false, nil).Once()

		result, err := service.ValidateToken(tokenString)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, userID, result.UserID)
		mockRevocation.AssertExpectations(t)
	})

	t.Run("token revoked", func(t *testing.T) {
		mockRevocation.On("IsTokenRevoked", claims.JTI).Return(true, nil).Once()

		result, err := service.ValidateToken(tokenString)

		require.Error(t, err)
		assert.Nil(t, result)
		testutils.AssertErrorType(t, ErrTokenRevoked, err)
		mockRevocation.AssertExpectations(t)
	})

	t.Run("revocation check error", func(t *testing.T) {
		mockRevocation.On("IsTokenRevoked", claims.JTI).Return(false, assert.AnError).Once()

		result, err := service.ValidateToken(tokenString)

		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "token validation failed")
		mockRevocation.AssertExpectations(t)
	})
}
