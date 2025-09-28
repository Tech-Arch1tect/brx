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
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/config"
)

func TestMiddleware(t *testing.T) {
	t.Run("with nil manager", func(t *testing.T) {
		middleware := Middleware(nil)
		c, _ := createTestContext()

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.True(t, called)
		assert.Nil(t, c.Get(sessionManagerKey))
	})

	t.Run("normal HTTP request", func(t *testing.T) {
		store := NewMemoryStore()
		sessionManager := scs.New()
		sessionManager.Store = store
		sessionManager.Cookie.Name = "test-session"

		manager := &Manager{
			SessionManager: sessionManager,
			config: config.SessionConfig{
				MaxAge: time.Hour,
			},
		}

		middleware := Middleware(manager)
		c, _ := createTestContext()

		called := false
		handler := func(c echo.Context) error {
			called = true

			manager := GetManager(c)
			assert.NotNil(t, manager)

			managerFromContext := GetManagerFromContext(c.Request().Context())
			assert.NotNil(t, managerFromContext)

			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("WebSocket upgrade request", func(t *testing.T) {
		store := NewMemoryStore()
		sessionManager := scs.New()
		sessionManager.Store = store
		sessionManager.Cookie.Name = "test-session"

		manager := &Manager{
			SessionManager: sessionManager,
			config: config.SessionConfig{
				MaxAge: time.Hour,
			},
		}

		middleware := Middleware(manager)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		called := false
		handler := func(c echo.Context) error {
			called = true

			manager := GetManager(c)
			assert.NotNil(t, manager)

			managerFromContext := GetManagerFromContext(c.Request().Context())
			assert.NotNil(t, managerFromContext)

			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("WebSocket with existing session cookie", func(t *testing.T) {
		store := NewMemoryStore()
		sessionManager := scs.New()
		sessionManager.Store = store
		sessionManager.Cookie.Name = "test-session"

		ctx := context.Background()
		ctx, err := sessionManager.Load(ctx, "")
		require.NoError(t, err)

		token, _, err := sessionManager.Commit(ctx)
		require.NoError(t, err)

		manager := &Manager{
			SessionManager: sessionManager,
			config: config.SessionConfig{
				MaxAge: time.Hour,
			},
		}

		middleware := Middleware(manager)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.AddCookie(&http.Cookie{
			Name:  "test-session",
			Value: token,
		})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err = middleware(handler)(c)

		assert.NoError(t, err)
		assert.True(t, called)
	})
}

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name       string
		connection string
		upgrade    string
		expected   bool
	}{
		{
			name:       "WebSocket upgrade",
			connection: "Upgrade",
			upgrade:    "websocket",
			expected:   true,
		},
		{
			name:       "WebSocket upgrade with additional connection values",
			connection: "keep-alive, Upgrade",
			upgrade:    "websocket",
			expected:   true,
		},
		{
			name:       "WebSocket upgrade case insensitive",
			connection: "upgrade",
			upgrade:    "WebSocket",
			expected:   true,
		},
		{
			name:       "Non-WebSocket upgrade",
			connection: "Upgrade",
			upgrade:    "h2c",
			expected:   false,
		},
		{
			name:       "No upgrade header",
			connection: "keep-alive",
			upgrade:    "",
			expected:   false,
		},
		{
			name:       "No connection header",
			connection: "",
			upgrade:    "websocket",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.connection != "" {
				req.Header.Set("Connection", tt.connection)
			}
			if tt.upgrade != "" {
				req.Header.Set("Upgrade", tt.upgrade)
			}

			result := isWebSocketUpgrade(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResponseWriterWrapper(t *testing.T) {
	t.Run("Header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		echo := &echo.Response{Writer: rec}
		wrapper := &responseWriterWrapper{
			ResponseWriter: rec,
			echo:           echo,
		}

		wrapper.Header().Set("Test-Header", "test-value")

		assert.Equal(t, "test-value", rec.Header().Get("Test-Header"))
	})

	t.Run("Write", func(t *testing.T) {
		rec := httptest.NewRecorder()
		echo := &echo.Response{Writer: rec}
		wrapper := &responseWriterWrapper{
			ResponseWriter: rec,
			echo:           echo,
		}

		data := []byte("test data")
		n, err := wrapper.Write(data)

		assert.NoError(t, err)
		assert.Equal(t, len(data), n)
		assert.Equal(t, "test data", rec.Body.String())
	})

	t.Run("WriteHeader", func(t *testing.T) {
		rec := httptest.NewRecorder()
		echo := &echo.Response{Writer: rec, Status: 0}
		wrapper := &responseWriterWrapper{
			ResponseWriter: rec,
			echo:           echo,
		}

		wrapper.WriteHeader(201)

		assert.Equal(t, 201, echo.Status)
		assert.Equal(t, 201, rec.Code)
	})

	t.Run("WriteHeader with existing status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		echo := &echo.Response{Writer: rec, Status: 200}
		wrapper := &responseWriterWrapper{
			ResponseWriter: rec,
			echo:           echo,
		}

		wrapper.WriteHeader(201)

		assert.Equal(t, 200, echo.Status)
	})
}

func TestGetManager(t *testing.T) {
	t.Run("manager exists", func(t *testing.T) {
		c, _ := createTestContext()
		expectedManager := setupTestSessionManager()
		c.Set(sessionManagerKey, expectedManager)

		manager := GetManager(c)

		assert.Equal(t, expectedManager, manager)
	})

	t.Run("manager does not exist", func(t *testing.T) {
		c, _ := createTestContext()

		manager := GetManager(c)

		assert.Nil(t, manager)
	})
}

func TestGetManagerFromContext(t *testing.T) {
	t.Run("manager exists in context", func(t *testing.T) {
		expectedManager := setupTestSessionManager()
		ctx := context.WithValue(context.Background(), sessionManagerContextKey, expectedManager)

		manager := GetManagerFromContext(ctx)

		assert.Equal(t, expectedManager, manager)
	})

	t.Run("manager does not exist in context", func(t *testing.T) {
		ctx := context.Background()

		manager := GetManagerFromContext(ctx)

		assert.Nil(t, manager)
	})
}

func TestSessionServiceMiddleware(t *testing.T) {
	t.Run("with session service and authenticated user", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		sessionService := NewSessionService(db, manager, nil)

		middleware := SessionServiceMiddleware(sessionService)

		c, _ := createTestContext()
		setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		sessionManager := GetManagerFromContext(ctx)
		sessionManager.Put(ctx, AuthenticatedKey, true)
		sessionManager.Put(ctx, UserIDKey, uint(123))

		called := false
		handler := func(c echo.Context) error {
			called = true

			service := GetSessionService(c)
			assert.Equal(t, sessionService, service)

			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("with session service but unauthenticated user", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		sessionService := NewSessionService(db, manager, nil)

		middleware := SessionServiceMiddleware(sessionService)

		c, _ := createTestContext()
		setupContextWithSessionManager(c)

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("without session service", func(t *testing.T) {
		middleware := SessionServiceMiddleware(nil)

		c, _ := createTestContext()

		called := false
		handler := func(c echo.Context) error {
			called = true

			service := GetSessionService(c)
			assert.Nil(t, service)

			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("with authenticated user but no session manager", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		sessionService := NewSessionService(db, manager, nil)

		middleware := SessionServiceMiddleware(sessionService)

		c, _ := createTestContext()

		called := false
		handler := func(c echo.Context) error {
			called = true
			return nil
		}

		err := middleware(handler)(c)

		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("handler returns error", func(t *testing.T) {
		middleware := SessionServiceMiddleware(nil)

		c, _ := createTestContext()

		expectedError := echo.NewHTTPError(500, "test error")
		handler := func(c echo.Context) error {
			return expectedError
		}

		err := middleware(handler)(c)

		assert.Equal(t, expectedError, err)
	})
}

func TestContextKeys(t *testing.T) {
	assert.Equal(t, "session_manager", string(sessionManagerContextKey))
	assert.Equal(t, "session_manager", sessionManagerKey)
	assert.Equal(t, "session_service", sessionServiceKey)
}
