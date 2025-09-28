package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/config"
)

func TestMiddleware(t *testing.T) {
	t.Run("basic rate limiting", func(t *testing.T) {
		cfg := &Config{
			Store:  NewMemoryStore(),
			Rate:   1,
			Period: time.Minute,
			KeyGenerator: func(c echo.Context) string {
				return "test-key"
			},
		}

		middleware := Middleware(cfg)

		e := echo.New()
		handler := func(c echo.Context) error {
			return c.String(http.StatusOK, "test")
		}

		req1 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec1 := httptest.NewRecorder()
		c1 := e.NewContext(req1, rec1)

		err := middleware(handler)(c1)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if rec1.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec1.Code)
		}

		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)

		err = middleware(handler)(c2)
		if err == nil {
			t.Error("expected rate limit error")
		} else {
			if httpErr, ok := err.(*echo.HTTPError); ok {
				if httpErr.Code != http.StatusTooManyRequests {
					t.Errorf("expected status %d, got %d", http.StatusTooManyRequests, httpErr.Code)
				}
			} else {
				t.Errorf("expected echo.HTTPError, got %T", err)
			}
		}
	})

	t.Run("default configuration", func(t *testing.T) {
		cfg := &Config{}
		middleware := Middleware(cfg)

		if cfg.Store == nil {
			t.Error("expected default store to be set")
		}
		if cfg.Rate != 10 {
			t.Errorf("expected default rate 10, got %d", cfg.Rate)
		}
		if cfg.Period != time.Minute {
			t.Errorf("expected default period 1 minute, got %v", cfg.Period)
		}
		if cfg.KeyGenerator == nil {
			t.Error("expected default key generator to be set")
		}
		if cfg.OnLimitReached == nil {
			t.Error("expected default limit reached handler to be set")
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

	t.Run("headers are set correctly", func(t *testing.T) {
		cfg := &Config{
			Store:  NewMemoryStore(),
			Rate:   5,
			Period: time.Minute,
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

		limitHeader := rec.Header().Get("X-RateLimit-Limit")
		if limitHeader != "5" {
			t.Errorf("expected X-RateLimit-Limit: 5, got %s", limitHeader)
		}

		remainingHeader := rec.Header().Get("X-RateLimit-Remaining")
		if remainingHeader != "4" {
			t.Errorf("expected X-RateLimit-Remaining: 4, got %s", remainingHeader)
		}

		resetHeader := rec.Header().Get("X-RateLimit-Reset")
		if resetHeader == "" {
			t.Error("expected X-RateLimit-Reset header to be set")
		}
	})

	t.Run("count mode: count all", func(t *testing.T) {
		cfg := &Config{
			Store:     NewMemoryStore(),
			Rate:      2,
			Period:    time.Minute,
			CountMode: config.CountAll,
		}

		middleware := Middleware(cfg)

		e := echo.New()
		handler := func(c echo.Context) error {
			return c.String(http.StatusInternalServerError, "error")
		}

		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := middleware(handler)(c)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middleware(handler)(c)
		if err == nil {
			t.Error("expected rate limit error")
		}
	})

	t.Run("count mode: count failures", func(t *testing.T) {
		cfg := &Config{
			Store:     NewMemoryStore(),
			Rate:      1,
			Period:    time.Minute,
			CountMode: config.CountFailures,
			KeyGenerator: func(c echo.Context) string {
				return "test-key-failures"
			},
		}

		middleware := Middleware(cfg)

		e := echo.New()

		successHandler := func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		}

		req1 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec1 := httptest.NewRecorder()
		c1 := e.NewContext(req1, rec1)

		err := middleware(successHandler)(c1)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		failureHandler := func(c echo.Context) error {
			return c.String(http.StatusInternalServerError, "error")
		}

		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)

		err = middleware(failureHandler)(c2)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		req3 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec3 := httptest.NewRecorder()
		c3 := e.NewContext(req3, rec3)

		err = middleware(failureHandler)(c3)
		if err != nil {
			if httpErr, ok := err.(*echo.HTTPError); ok {
				if httpErr.Code != http.StatusTooManyRequests {
					t.Errorf("expected status %d, got %d", http.StatusTooManyRequests, httpErr.Code)
				}
			} else {
				t.Errorf("expected echo.HTTPError, got %T", err)
			}
		} else {
			t.Error("expected rate limit error")
		}
	})

	t.Run("count mode: count success", func(t *testing.T) {
		cfg := &Config{
			Store:     NewMemoryStore(),
			Rate:      1,
			Period:    time.Minute,
			CountMode: config.CountSuccess,
			KeyGenerator: func(c echo.Context) string {
				return "test-key-success"
			},
		}

		middleware := Middleware(cfg)

		e := echo.New()

		successHandler := func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		}

		req1 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec1 := httptest.NewRecorder()
		c1 := e.NewContext(req1, rec1)

		err := middleware(successHandler)(c1)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)

		err = middleware(successHandler)(c2)
		if err == nil {
			t.Error("expected rate limit error")
		}
	})

	t.Run("custom key generator", func(t *testing.T) {
		cfg := &Config{
			Store:  NewMemoryStore(),
			Rate:   1,
			Period: time.Minute,
			KeyGenerator: func(c echo.Context) string {
				return "custom-key"
			},
		}

		middleware := Middleware(cfg)

		e := echo.New()
		handler := func(c echo.Context) error {
			return c.String(http.StatusOK, "test")
		}

		req1 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec1 := httptest.NewRecorder()
		c1 := e.NewContext(req1, rec1)

		err := middleware(handler)(c1)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)

		err = middleware(handler)(c2)
		if err == nil {
			t.Error("expected rate limit error")
		} else {
			if httpErr, ok := err.(*echo.HTTPError); ok {
				if httpErr.Code != http.StatusTooManyRequests {
					t.Errorf("expected status %d, got %d", http.StatusTooManyRequests, httpErr.Code)
				}
			} else {
				t.Errorf("expected echo.HTTPError, got %T", err)
			}
		}
	})

	t.Run("custom limit reached handler", func(t *testing.T) {
		customErrorCalled := false
		cfg := &Config{
			Store:  NewMemoryStore(),
			Rate:   1,
			Period: time.Minute,
			KeyGenerator: func(c echo.Context) string {
				return "test-key-custom"
			},
			OnLimitReached: func(c echo.Context) error {
				customErrorCalled = true
				return c.String(http.StatusTooManyRequests, "Custom limit reached")
			},
		}

		middleware := Middleware(cfg)

		e := echo.New()
		handler := func(c echo.Context) error {
			return c.String(http.StatusOK, "test")
		}

		req1 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec1 := httptest.NewRecorder()
		c1 := e.NewContext(req1, rec1)

		err := middleware(handler)(c1)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)

		err = middleware(handler)(c2)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if !customErrorCalled {
			t.Error("expected custom limit reached handler to be called")
		}

		if rec2.Code != http.StatusTooManyRequests {
			t.Errorf("expected status %d, got %d", http.StatusTooManyRequests, rec2.Code)
		}
	})
}

func TestDefaultKeyGenerator(t *testing.T) {
	e := echo.New()

	t.Run("normal IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Real-IP", "192.168.1.1")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		key := DefaultKeyGenerator(c)
		expected := "rate_limit:192.168.1.1"
		if key != expected {
			t.Errorf("expected key %q, got %q", expected, key)
		}
	})

	t.Run("fallback for empty IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		key := DefaultKeyGenerator(c)

		if !strings.Contains(key, "rate_limit:") {
			t.Errorf("expected key to contain rate_limit prefix, got %q", key)
		}
	})
}

func TestSecureKeyGenerator(t *testing.T) {
	e := echo.New()

	t.Run("with user agent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Real-IP", "192.168.1.1")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		key := SecureKeyGenerator(c)
		if key == "" {
			t.Error("expected non-empty key")
		}
		if !contains(key, "rate_limit:192.168.1.1:") {
			t.Errorf("expected key to contain rate_limit and IP, got %q", key)
		}
	})

	t.Run("fallback for empty IP and UA", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		key := SecureKeyGenerator(c)

		if !strings.Contains(key, "rate_limit:") || !strings.Contains(key, ":none") {
			t.Errorf("expected key to contain rate_limit prefix and :none suffix, got %q", key)
		}
	})
}

func TestSimpleHash(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "none"},
		{"test", "364492"},
		{"Mozilla/5.0", "7392ff"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := simpleHash(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestDefaultOnLimitReached(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := DefaultOnLimitReached(c)
	if err == nil {
		t.Error("expected error to be returned")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Error("expected echo.HTTPError")
	}

	if httpErr.Code != http.StatusTooManyRequests {
		t.Errorf("expected status %d, got %d", http.StatusTooManyRequests, httpErr.Code)
	}
}

func TestNewStore(t *testing.T) {
	t.Run("memory store", func(t *testing.T) {
		cfg := &config.RateLimitConfig{
			Store: "memory",
		}

		store := NewStore(cfg)
		if store == nil {
			t.Error("expected store to be created")
		}

		if _, ok := store.(*MemoryStore); !ok {
			t.Error("expected MemoryStore")
		}
	})

	t.Run("default store", func(t *testing.T) {
		cfg := &config.RateLimitConfig{
			Store: "unknown",
		}

		store := NewStore(cfg)
		if store == nil {
			t.Error("expected store to be created")
		}

		if _, ok := store.(*MemoryStore); !ok {
			t.Error("expected MemoryStore as default")
		}
	})
}

func TestWithConfig(t *testing.T) {
	cfg := &Config{
		Rate:   5,
		Period: time.Minute,
	}

	middleware := WithConfig(cfg)
	if middleware == nil {
		t.Error("expected middleware to be returned")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		(len(s) > len(substr) && contains(s[1:], substr))
}
