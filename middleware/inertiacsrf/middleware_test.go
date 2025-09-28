package inertiacsrf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/config"
)

func TestMiddleware(t *testing.T) {
	t.Run("CSRF disabled", func(t *testing.T) {
		cfg := &config.Config{
			CSRF: config.CSRFConfig{
				Enabled: false,
			},
		}

		middleware := Middleware(cfg)
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
	})

	t.Run("CSRF enabled with token", func(t *testing.T) {
		cfg := &config.Config{
			CSRF: config.CSRFConfig{
				Enabled:    true,
				ContextKey: "csrf",
			},
		}

		middleware := Middleware(cfg)
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

		expectedToken := "test-csrf-token"
		c.Set("csrf", expectedToken)

		err := middleware(handler)(c)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("static asset paths excluded", func(t *testing.T) {
		cfg := &config.Config{
			CSRF: config.CSRFConfig{
				Enabled:    true,
				ContextKey: "csrf",
			},
		}

		middleware := Middleware(cfg)

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

				c.Set("csrf", "test-token")

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

	t.Run("no token set", func(t *testing.T) {
		cfg := &config.Config{
			CSRF: config.CSRFConfig{
				Enabled:    true,
				ContextKey: "csrf",
			},
		}

		middleware := Middleware(cfg)

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
