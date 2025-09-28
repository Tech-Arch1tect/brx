package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/config"
)

type MockTOTPChecker struct {
	mock.Mock
}

func (m *MockTOTPChecker) IsUserTOTPEnabled(userID uint) bool {
	args := m.Called(userID)
	return args.Bool(0)
}

func createTestContext() (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func setupContextWithSessionManager(c echo.Context) *Manager {
	store := NewMemoryStore()
	sessionManager := scs.New()
	sessionManager.Store = store

	manager := &Manager{
		SessionManager: sessionManager,
		config: config.SessionConfig{
			MaxAge: time.Hour,
		},
	}

	c.Set(sessionManagerKey, manager)

	ctx := c.Request().Context()
	ctx = context.WithValue(ctx, sessionManagerContextKey, manager)

	loadedCtx, err := sessionManager.Load(ctx, "")
	if err == nil {
		ctx = loadedCtx
	}

	c.SetRequest(c.Request().WithContext(ctx))

	return manager
}

func TestLogin(t *testing.T) {
	t.Run("successful login without TOTP service", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		Login(c, uint(123))

		ctx := c.Request().Context()
		assert.Equal(t, uint(123), manager.Get(ctx, UserIDKey))
		assert.True(t, manager.GetBool(ctx, AuthenticatedKey))
		assert.False(t, manager.GetBool(ctx, TOTPEnabledKey))
		assert.False(t, manager.GetBool(ctx, TOTPVerifiedKey))
	})

	t.Run("without session manager", func(t *testing.T) {
		c, _ := createTestContext()

		Login(c, uint(123))
	})
}

func TestLoginWithTOTPService(t *testing.T) {
	t.Run("login with TOTP enabled", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)
		mockTOTP := &MockTOTPChecker{}

		mockTOTP.On("IsUserTOTPEnabled", uint(123)).Return(true)

		LoginWithTOTPService(c, uint(123), mockTOTP)

		ctx := c.Request().Context()
		assert.Equal(t, uint(123), manager.Get(ctx, UserIDKey))
		assert.True(t, manager.GetBool(ctx, AuthenticatedKey))
		assert.True(t, manager.GetBool(ctx, TOTPEnabledKey))
		assert.False(t, manager.GetBool(ctx, TOTPVerifiedKey))

		mockTOTP.AssertExpectations(t)
	})

	t.Run("login with TOTP disabled", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)
		mockTOTP := &MockTOTPChecker{}

		mockTOTP.On("IsUserTOTPEnabled", uint(123)).Return(false)

		LoginWithTOTPService(c, uint(123), mockTOTP)

		ctx := c.Request().Context()
		assert.Equal(t, uint(123), manager.Get(ctx, UserIDKey))
		assert.True(t, manager.GetBool(ctx, AuthenticatedKey))
		assert.False(t, manager.GetBool(ctx, TOTPEnabledKey))

		mockTOTP.AssertExpectations(t)
	})

	t.Run("login with session service tracking", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		db := setupTestDB(t)
		sessionService := NewSessionService(db, manager, nil)
		c.Set(sessionServiceKey, sessionService)

		ctx := c.Request().Context()
		token, _, err := manager.SessionManager.Commit(ctx)
		require.NoError(t, err)

		ctx, err = manager.SessionManager.Load(ctx, token)
		require.NoError(t, err)
		c.SetRequest(c.Request().WithContext(ctx))

		LoginWithTOTPService(c, uint(123), nil)

		updatedToken := manager.Token(ctx)
		if updatedToken == "" {
			updatedToken = token
		}

		var session UserSession
		err = db.Where("token = ?", updatedToken).First(&session).Error
		require.NoError(t, err)
		assert.Equal(t, uint(123), session.UserID)
		assert.Equal(t, SessionTypeWeb, session.Type)
	})

	t.Run("login with invalid user ID type", func(t *testing.T) {
		c, _ := createTestContext()
		setupContextWithSessionManager(c)

		LoginWithTOTPService(c, "invalid", nil)
	})

	t.Run("without session manager", func(t *testing.T) {
		c, _ := createTestContext()

		LoginWithTOTPService(c, uint(123), nil)
	})
}

func TestLogout(t *testing.T) {
	t.Run("successful logout", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, UserIDKey, uint(123))
		manager.Put(ctx, AuthenticatedKey, true)
		manager.Put(ctx, TOTPVerifiedKey, true)
		manager.Put(ctx, TOTPEnabledKey, true)

		Logout(c)

		assert.Nil(t, manager.Get(ctx, UserIDKey))
		assert.False(t, manager.GetBool(ctx, AuthenticatedKey))
		assert.False(t, manager.GetBool(ctx, TOTPVerifiedKey))
		assert.False(t, manager.GetBool(ctx, TOTPEnabledKey))
	})

	t.Run("logout with session service", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		db := setupTestDB(t)
		sessionService := NewSessionService(db, manager, nil)
		c.Set(sessionServiceKey, sessionService)

		ctx := c.Request().Context()
		token, _, err := manager.SessionManager.Commit(ctx)
		require.NoError(t, err)

		ctx, err = manager.SessionManager.Load(ctx, token)
		require.NoError(t, err)
		c.SetRequest(c.Request().WithContext(ctx))

		err = sessionService.TrackSession(123, token, SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		Logout(c)

		exists, err := sessionService.SessionExists(token)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("without session manager", func(t *testing.T) {
		c, _ := createTestContext()

		Logout(c)
	})
}

func TestGetUserID(t *testing.T) {
	t.Run("user ID exists", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, UserIDKey, uint(123))

		userID := GetUserID(c)

		assert.Equal(t, uint(123), userID)
	})

	t.Run("user ID does not exist", func(t *testing.T) {
		c, _ := createTestContext()
		setupContextWithSessionManager(c)

		userID := GetUserID(c)

		assert.Nil(t, userID)
	})

	t.Run("without session manager", func(t *testing.T) {
		c, _ := createTestContext()

		userID := GetUserID(c)

		assert.Nil(t, userID)
	})
}

func TestGetUserIDAsString(t *testing.T) {
	t.Run("user ID exists", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, UserIDKey, "123")

		userID := GetUserIDAsString(c)

		assert.Equal(t, "123", userID)
	})

	t.Run("without session manager", func(t *testing.T) {
		c, _ := createTestContext()

		userID := GetUserIDAsString(c)

		assert.Equal(t, "", userID)
	})
}

func TestGetUserIDAsInt(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		expected int
	}{
		{"int", 123, 123},
		{"uint", uint(123), 123},
		{"int64", int64(123), 123},
		{"uint64", uint64(123), 123},
		{"float64", float64(123), 123},
		{"string", "123", 0},
		{"nil", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := createTestContext()
			manager := setupContextWithSessionManager(c)

			ctx := c.Request().Context()
			if tt.value != nil {
				manager.Put(ctx, UserIDKey, tt.value)
			}

			result := GetUserIDAsInt(c)

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetUserIDAsUint(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		expected uint
	}{
		{"uint", uint(123), 123},
		{"int", 123, 123},
		{"int64", int64(123), 123},
		{"uint64", uint64(123), 123},
		{"float64", float64(123), 123},
		{"string", "123", 0},
		{"nil", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := createTestContext()
			manager := setupContextWithSessionManager(c)

			ctx := c.Request().Context()
			if tt.value != nil {
				manager.Put(ctx, UserIDKey, tt.value)
			}

			result := GetUserIDAsUint(c)

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsAuthenticated(t *testing.T) {
	t.Run("authenticated", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, AuthenticatedKey, true)

		result := IsAuthenticated(c)

		assert.True(t, result)
	})

	t.Run("not authenticated", func(t *testing.T) {
		c, _ := createTestContext()
		setupContextWithSessionManager(c)

		result := IsAuthenticated(c)

		assert.False(t, result)
	})

	t.Run("without session manager", func(t *testing.T) {
		c, _ := createTestContext()

		result := IsAuthenticated(c)

		assert.False(t, result)
	})
}

func TestRequireAuth(t *testing.T) {
	middleware := RequireAuth()

	t.Run("authenticated user", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, AuthenticatedKey, true)

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("unauthenticated user", func(t *testing.T) {
		c, _ := createTestContext()
		setupContextWithSessionManager(c)

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.Error(t, err)
		assert.False(t, called)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, 401, httpError.Code)
	})
}

func TestRequireAuthWeb(t *testing.T) {
	middleware := RequireAuthWeb("/login")

	t.Run("authenticated user", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, AuthenticatedKey, true)

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("unauthenticated user", func(t *testing.T) {
		c, rec := createTestContext()
		setupContextWithSessionManager(c)

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.False(t, called)
		assert.Equal(t, 302, rec.Code)
		assert.Equal(t, "/login", rec.Header().Get("Location"))
	})
}

func TestSessionHelpers(t *testing.T) {
	t.Run("Set and Get", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		Set(c, "test_key", "test_value")
		value := Get(c, "test_key")

		assert.Equal(t, "test_value", value)

		ctx := c.Request().Context()
		assert.Equal(t, "test_value", manager.Get(ctx, "test_key"))
	})

	t.Run("Delete", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, "test_key", "test_value")

		Delete(c, "test_key")

		assert.Nil(t, manager.Get(ctx, "test_key"))
	})

	t.Run("operations without session manager", func(t *testing.T) {
		c, _ := createTestContext()

		Set(c, "test_key", "test_value")
		value := Get(c, "test_key")
		Delete(c, "test_key")

		assert.Nil(t, value)
	})
}

func TestGetSessionService(t *testing.T) {
	t.Run("service exists", func(t *testing.T) {
		c, _ := createTestContext()
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		expectedService := NewSessionService(db, manager, nil)

		c.Set(sessionServiceKey, expectedService)

		service := GetSessionService(c)

		assert.Equal(t, expectedService, service)
	})

	t.Run("service does not exist", func(t *testing.T) {
		c, _ := createTestContext()

		service := GetSessionService(c)

		assert.Nil(t, service)
	})

	t.Run("invalid service type", func(t *testing.T) {
		c, _ := createTestContext()
		c.Set(sessionServiceKey, "invalid")

		service := GetSessionService(c)

		assert.Nil(t, service)
	})
}

func TestTOTPHelpers(t *testing.T) {
	t.Run("SetTOTPVerified and IsTOTPVerified", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		SetTOTPVerified(c, true)
		verified := IsTOTPVerified(c)

		assert.True(t, verified)

		ctx := c.Request().Context()
		assert.True(t, manager.GetBool(ctx, TOTPVerifiedKey))
	})

	t.Run("ClearTOTPVerification", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, TOTPVerifiedKey, true)

		ClearTOTPVerification(c)

		assert.False(t, manager.GetBool(ctx, TOTPVerifiedKey))
	})

	t.Run("SetTOTPEnabled and IsTOTPEnabled", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		SetTOTPEnabled(c, true)
		enabled := IsTOTPEnabled(c)

		assert.True(t, enabled)

		ctx := c.Request().Context()
		assert.True(t, manager.GetBool(ctx, TOTPEnabledKey))
	})

	t.Run("operations without session manager", func(t *testing.T) {
		c, _ := createTestContext()

		SetTOTPVerified(c, true)
		verified := IsTOTPVerified(c)
		assert.False(t, verified)

		ClearTOTPVerification(c)

		SetTOTPEnabled(c, true)
		enabled := IsTOTPEnabled(c)
		assert.False(t, enabled)
	})
}

func TestRequireTOTP(t *testing.T) {
	middleware := RequireTOTP()

	t.Run("authenticated and TOTP verified", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, AuthenticatedKey, true)
		manager.Put(ctx, TOTPEnabledKey, true)
		manager.Put(ctx, TOTPVerifiedKey, true)

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("authenticated with TOTP disabled", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, AuthenticatedKey, true)
		manager.Put(ctx, TOTPEnabledKey, false)

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("authenticated with TOTP enabled but not verified", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, AuthenticatedKey, true)
		manager.Put(ctx, TOTPEnabledKey, true)
		manager.Put(ctx, TOTPVerifiedKey, false)

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.Error(t, err)
		assert.False(t, called)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, 401, httpError.Code)
		assert.Contains(t, httpError.Message, "TOTP verification required")
	})

	t.Run("unauthenticated", func(t *testing.T) {
		c, _ := createTestContext()
		setupContextWithSessionManager(c)

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.Error(t, err)
		assert.False(t, called)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, 401, httpError.Code)
		assert.Contains(t, httpError.Message, "Authentication required")
	})
}

func TestRequireTOTPWeb(t *testing.T) {
	middleware := RequireTOTPWeb("/totp")

	t.Run("authenticated and TOTP verified", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, AuthenticatedKey, true)
		manager.Put(ctx, TOTPEnabledKey, true)
		manager.Put(ctx, TOTPVerifiedKey, true)

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("authenticated with TOTP enabled but not verified", func(t *testing.T) {
		c, rec := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, AuthenticatedKey, true)
		manager.Put(ctx, TOTPEnabledKey, true)
		manager.Put(ctx, TOTPVerifiedKey, false)

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.False(t, called)
		assert.Equal(t, 302, rec.Code)
		assert.Equal(t, "/totp", rec.Header().Get("Location"))
	})

	t.Run("unauthenticated", func(t *testing.T) {
		c, rec := createTestContext()
		setupContextWithSessionManager(c)

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.False(t, called)
		assert.Equal(t, 302, rec.Code)
		assert.Equal(t, "/auth/login", rec.Header().Get("Location"))
	})
}

func TestConvertToUint(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected uint
	}{
		{"uint", uint(123), 123},
		{"int", 123, 123},
		{"int64", int64(123), 123},
		{"uint64", uint64(123), 123},
		{"float64", float64(123), 123},
		{"string", "123", 0},
		{"nil", nil, 0},
		{"bool", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertToUint(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
