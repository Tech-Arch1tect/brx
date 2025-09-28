package csrf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/config"
)

func TestMiddleware(t *testing.T) {
	t.Run("CSRF disabled", func(t *testing.T) {
		cfg := &config.CSRFConfig{
			Enabled: false,
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

	t.Run("CSRF enabled", func(t *testing.T) {
		cfg := &config.CSRFConfig{
			Enabled:        true,
			TokenLength:    32,
			TokenLookup:    "header:X-CSRF-Token",
			ContextKey:     "csrf",
			CookieName:     "_csrf",
			CookieDomain:   "",
			CookiePath:     "/",
			CookieMaxAge:   86400,
			CookieSecure:   false,
			CookieHTTPOnly: true,
			CookieSameSite: "strict",
		}

		middleware := Middleware(cfg)
		if middleware == nil {
			t.Fatal("expected middleware to be returned")
		}
	})

	t.Run("different SameSite values", func(t *testing.T) {
		sameSiteTests := []struct {
			name       string
			sameSite   string
			shouldWork bool
		}{
			{"strict", "strict", true},
			{"lax", "lax", true},
			{"none", "none", true},
			{"default", "default", true},
			{"invalid", "invalid", true},
		}

		for _, tt := range sameSiteTests {
			t.Run(tt.name, func(t *testing.T) {
				cfg := &config.CSRFConfig{
					Enabled:        true,
					TokenLength:    32,
					TokenLookup:    "header:X-CSRF-Token",
					ContextKey:     "csrf",
					CookieName:     "_csrf",
					CookieDomain:   "",
					CookiePath:     "/",
					CookieMaxAge:   86400,
					CookieSecure:   false,
					CookieHTTPOnly: true,
					CookieSameSite: tt.sameSite,
				}

				middleware := Middleware(cfg)
				if middleware == nil {
					t.Fatal("expected middleware to be returned")
				}
			})
		}
	})
}

func TestWithConfig(t *testing.T) {
	cfg := &config.CSRFConfig{
		Enabled: false,
	}

	middleware := WithConfig(cfg)
	if middleware == nil {
		t.Fatal("expected middleware to be returned")
	}
}

func TestGetToken(t *testing.T) {
	e := echo.New()

	t.Run("token exists", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		expectedToken := "test-token"
		c.Set("csrf", expectedToken)

		token := GetToken(c)
		if token != expectedToken {
			t.Errorf("expected token %q, got %q", expectedToken, token)
		}
	})

	t.Run("token does not exist", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		token := GetToken(c)
		if token != "" {
			t.Errorf("expected empty token, got %q", token)
		}
	})

	t.Run("token is wrong type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		c.Set("csrf", 123)

		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic when token is wrong type")
			}
		}()

		GetToken(c)
	})
}
