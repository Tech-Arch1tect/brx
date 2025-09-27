package jwt

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/services/jwt"
	"github.com/tech-arch1tect/brx/testutils"
)

func setupTestJWTService() *jwt.Service {
	cfg := testutils.GetTestConfig()
	return jwt.NewService(cfg, nil)
}

func TestRequireJWT(t *testing.T) {
	e := echo.New()
	jwtService := setupTestJWTService()
	middleware := RequireJWT(jwtService)

	successHandler := func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "success"})
	}

	t.Run("missing authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middleware(successHandler)(c)

		require.Error(t, err)
		httpError, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusUnauthorized, httpError.Code)
		assert.Contains(t, httpError.Message, "Authorization header required")
	})

	t.Run("invalid authorization header format", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Invalid token")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middleware(successHandler)(c)

		require.Error(t, err)
		httpError, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusUnauthorized, httpError.Code)
		assert.Contains(t, httpError.Message, "Invalid authorization header format")
	})

	t.Run("empty bearer token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer ")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middleware(successHandler)(c)

		require.Error(t, err)
		httpError, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusUnauthorized, httpError.Code)
		assert.Contains(t, httpError.Message, "JWT token required")
	})

	t.Run("invalid JWT token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid.jwt.token")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middleware(successHandler)(c)

		require.Error(t, err)
		httpError, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusUnauthorized, httpError.Code)
		assert.Contains(t, httpError.Message, "Authentication failed")
	})

	t.Run("valid JWT token", func(t *testing.T) {
		userID := uint(123)

		tokenString, err := jwtService.GenerateToken(userID)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = middleware(successHandler)(c)

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		assert.Equal(t, userID, c.Get(UserIDKey))
		claims, ok := c.Get(ClaimsKey).(*jwt.Claims)
		require.True(t, ok)
		assert.Equal(t, userID, claims.UserID)
		assert.NotEmpty(t, claims.JTI)
	})

	t.Run("expired JWT token", func(t *testing.T) {
		cfg := testutils.GetTestConfig()

		cfg.JWT.AccessExpiry = 1
		shortLivedService := jwt.NewService(cfg, nil)

		userID := uint(123)
		tokenString, err := shortLivedService.GenerateToken(userID)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		middleware := RequireJWT(shortLivedService)
		err = middleware(successHandler)(c)

		require.Error(t, err)
		httpError, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusUnauthorized, httpError.Code)
		assert.Contains(t, httpError.Message, "Authentication failed")
	})

	t.Run("bearer token with extra spaces", func(t *testing.T) {
		userID := uint(123)
		tokenString, err := jwtService.GenerateToken(userID)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer  "+tokenString+"  ")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = middleware(successHandler)(c)

		require.Error(t, err)
		httpError, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusUnauthorized, httpError.Code)
	})
}

func TestGetUserID(t *testing.T) {
	e := echo.New()

	t.Run("user ID exists in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		expectedUserID := uint(123)
		c.Set(UserIDKey, expectedUserID)

		userID := GetUserID(c)

		assert.Equal(t, expectedUserID, userID)
	})

	t.Run("user ID does not exist in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		userID := GetUserID(c)

		assert.Equal(t, uint(0), userID)
	})

	t.Run("user ID is wrong type in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		c.Set(UserIDKey, "not-a-uint")

		userID := GetUserID(c)

		assert.Equal(t, uint(0), userID)
	})
}

func TestGetClaims(t *testing.T) {
	e := echo.New()

	t.Run("claims exist in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		expectedClaims := &jwt.Claims{
			UserID: 123,
			JTI:    "test-jti",
		}
		c.Set(ClaimsKey, expectedClaims)

		claims := GetClaims(c)

		assert.Equal(t, expectedClaims, claims)
		assert.Equal(t, uint(123), claims.UserID)
		assert.Equal(t, "test-jti", claims.JTI)
	})

	t.Run("claims do not exist in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		claims := GetClaims(c)

		assert.Nil(t, claims)
	})

	t.Run("claims are wrong type in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		c.Set(ClaimsKey, "not-claims")

		claims := GetClaims(c)

		assert.Nil(t, claims)
	})
}

func TestRequireJWT_Integration(t *testing.T) {

	e := echo.New()
	jwtService := setupTestJWTService()

	e.GET("/protected", func(c echo.Context) error {
		userID := GetUserID(c)
		claims := GetClaims(c)

		return c.JSON(http.StatusOK, map[string]interface{}{
			"user_id": userID,
			"jti":     claims.JTI,
		})
	}, RequireJWT(jwtService))

	t.Run("complete flow with valid token", func(t *testing.T) {
		userID := uint(456)
		tokenString, err := jwtService.GenerateToken(userID)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"user_id":456`)
		assert.Contains(t, rec.Body.String(), `"jti"`)
	})

	t.Run("complete flow with missing token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "Authorization header required")
	})
}
