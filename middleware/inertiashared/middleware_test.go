package inertiashared

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
	t.Run("auth enabled without user provider", func(t *testing.T) {
		cfg := Config{
			AuthEnabled:  true,
			FlashEnabled: false,
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

		err := middleware(handler)(c)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("auth enabled with user provider", func(t *testing.T) {
		userProvider := &mockUserProvider{
			users: map[uint]any{
				1: map[string]string{"name": "Test User"},
			},
		}

		cfg := Config{
			AuthEnabled:  true,
			FlashEnabled: false,
			UserProvider: userProvider,
		}

		middleware := MiddlewareWithConfig(cfg)

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
	})

	t.Run("user provider returns error", func(t *testing.T) {
		userProvider := &mockUserProvider{
			err: errors.New("database error"),
		}

		cfg := Config{
			AuthEnabled:  true,
			FlashEnabled: false,
			UserProvider: userProvider,
		}

		middleware := MiddlewareWithConfig(cfg)

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
	})

	t.Run("static asset paths excluded", func(t *testing.T) {
		cfg := Config{
			AuthEnabled:  true,
			FlashEnabled: true,
			UserProvider: nil,
		}

		middleware := MiddlewareWithConfig(cfg)

		staticPaths := []string{
			"/build/app.js",
			"/assets/style.css",
			"/.well-known/security.txt",
		}

		for _, path := range staticPaths {
			t.Run(path, func(t *testing.T) {
				e := echo.New()
				handler := func(c echo.Context) error {
					return c.String(http.StatusOK, "static")
				}

				req := httptest.NewRequest(http.MethodGet, path, nil)
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
	})

	t.Run("flash enabled", func(t *testing.T) {
		cfg := Config{
			AuthEnabled:  false,
			FlashEnabled: true,
			UserProvider: nil,
		}

		middleware := MiddlewareWithConfig(cfg)

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
	})

	t.Run("all features disabled", func(t *testing.T) {
		cfg := Config{
			AuthEnabled:  false,
			FlashEnabled: false,
			UserProvider: nil,
		}

		middleware := MiddlewareWithConfig(cfg)

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
	})
}
