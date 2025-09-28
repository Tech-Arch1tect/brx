package jwtshared

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

type mockUserProvider struct {
	users map[uint]any
	err   error
}

func (m *mockUserProvider) GetUser(userID uint) (any, error) {
	if m.err != nil {
		return nil, m.err
	}
	if user, exists := m.users[userID]; exists {
		return user, nil
	}
	return nil, nil
}

func TestMiddleware(t *testing.T) {
	middleware := Middleware()
	if middleware == nil {
		t.Fatal("expected middleware to be returned")
	}

	e := echo.New()
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := middleware(handler)(c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestMiddlewareWithConfig(t *testing.T) {
	t.Run("no user provider", func(t *testing.T) {
		cfg := Config{
			UserProvider: nil,
		}

		middleware := MiddlewareWithConfig(cfg)
		if middleware == nil {
			t.Fatal("expected middleware to be returned")
		}

		e := echo.New()
		handler := func(c echo.Context) error {
			return c.String(http.StatusOK, "test")
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		c.Set("_jwt_user_id", uint(1))

		err := middleware(handler)(c)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("with user provider and valid user", func(t *testing.T) {
		userProvider := &mockUserProvider{
			users: map[uint]any{
				1: map[string]string{"name": "Test User"},
			},
		}

		cfg := Config{
			UserProvider: userProvider,
		}

		middleware := MiddlewareWithConfig(cfg)

		e := echo.New()
		handler := func(c echo.Context) error {
			currentUser := c.Get("currentUser")
			if currentUser == nil {
				t.Error("expected currentUser to be set")
			}
			return c.String(http.StatusOK, "test")
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		c.Set("_jwt_user_id", uint(1))

		err := middleware(handler)(c)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("user provider returns error", func(t *testing.T) {
		userProvider := &mockUserProvider{
			err: errors.New("database error"),
		}

		cfg := Config{
			UserProvider: userProvider,
		}

		middleware := MiddlewareWithConfig(cfg)

		e := echo.New()
		handler := func(c echo.Context) error {
			currentUser := c.Get("currentUser")
			if currentUser != nil {
				t.Error("expected currentUser to be nil when error occurs")
			}
			return c.String(http.StatusOK, "test")
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		c.Set("_jwt_user_id", uint(1))

		err := middleware(handler)(c)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		userProvider := &mockUserProvider{
			users: map[uint]any{},
		}

		cfg := Config{
			UserProvider: userProvider,
		}

		middleware := MiddlewareWithConfig(cfg)

		e := echo.New()
		handler := func(c echo.Context) error {
			currentUser := c.Get("currentUser")
			if currentUser != nil {
				t.Error("expected currentUser to be nil when user not found")
			}
			return c.String(http.StatusOK, "test")
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		c.Set("userID", uint(999))

		err := middleware(handler)(c)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("no userID set", func(t *testing.T) {
		userProvider := &mockUserProvider{
			users: map[uint]any{
				1: map[string]string{"name": "Test User"},
			},
		}

		cfg := Config{
			UserProvider: userProvider,
		}

		middleware := MiddlewareWithConfig(cfg)

		e := echo.New()
		handler := func(c echo.Context) error {
			currentUser := c.Get("currentUser")
			if currentUser != nil {
				t.Error("expected currentUser to be nil when no userID set")
			}
			return c.String(http.StatusOK, "test")
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middleware(handler)(c)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})
}

func TestGetCurrentUser(t *testing.T) {
	e := echo.New()

	t.Run("user exists", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		expectedUser := map[string]string{"name": "Test User"}
		c.Set("currentUser", expectedUser)

		user := GetCurrentUser(c)
		if user == nil {
			t.Error("expected user to be set, got nil")
		}
	})

	t.Run("user does not exist", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		user := GetCurrentUser(c)
		if user != nil {
			t.Errorf("expected nil user, got %v", user)
		}
	})
}
