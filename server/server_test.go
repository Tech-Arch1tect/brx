package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
)

func TestNew(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: "8080",
		},
	}

	t.Run("with logger", func(t *testing.T) {
		loggerService := &logging.Service{}
		server := New(cfg, loggerService)

		if server == nil {
			t.Fatal("expected server to be created")
		}
		if server.cfg != cfg {
			t.Error("expected config to be set")
		}
		if server.logger != loggerService {
			t.Error("expected logger to be set")
		}
		if server.echo == nil {
			t.Error("expected echo instance to be created")
		}
	})

	t.Run("without logger", func(t *testing.T) {
		server := New(cfg, nil)

		if server == nil {
			t.Fatal("expected server to be created")
		}
		if server.cfg != cfg {
			t.Error("expected config to be set")
		}
		if server.logger != nil {
			t.Error("expected logger to be nil")
		}
		if server.echo == nil {
			t.Error("expected echo instance to be created")
		}
	})
}

func TestServer_HTTPMethods(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: "8080",
		},
	}
	server := New(cfg, nil)

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	}

	t.Run("GET", func(t *testing.T) {
		server.Get("/test", handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		server.echo.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("POST", func(t *testing.T) {
		server.Post("/test-post", handler)

		req := httptest.NewRequest(http.MethodPost, "/test-post", nil)
		rec := httptest.NewRecorder()
		server.echo.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("PUT", func(t *testing.T) {
		server.Put("/test-put", handler)

		req := httptest.NewRequest(http.MethodPut, "/test-put", nil)
		rec := httptest.NewRecorder()
		server.echo.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("DELETE", func(t *testing.T) {
		server.Delete("/test-delete", handler)

		req := httptest.NewRequest(http.MethodDelete, "/test-delete", nil)
		rec := httptest.NewRecorder()
		server.echo.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("PATCH", func(t *testing.T) {
		server.Patch("/test-patch", handler)

		req := httptest.NewRequest(http.MethodPatch, "/test-patch", nil)
		rec := httptest.NewRecorder()
		server.echo.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})
}

func TestServer_Group(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: "8080",
		},
	}
	server := New(cfg, nil)

	group := server.Group("/api")
	if group == nil {
		t.Fatal("expected group to be created")
	}

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "api test")
	}
	group.GET("/test", handler)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()
	server.echo.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "api test" {
		t.Errorf("expected 'api test', got '%s'", strings.TrimSpace(rec.Body.String()))
	}
}

func TestServer_SetRenderer(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: "8080",
		},
	}
	server := New(cfg, nil)

	mockRenderer := &mockRenderer{}
	server.SetRenderer(mockRenderer)

	if server.echo.Renderer == nil {
		t.Error("expected renderer to be set")
	}
}

func TestServer_Echo(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: "8080",
		},
	}
	server := New(cfg, nil)

	echo := server.Echo()
	if echo != server.echo {
		t.Error("expected Echo() to return the internal echo instance")
	}
}

func TestConfigureTrustedProxies(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		expectDirect   bool
	}{
		{
			name:           "no trusted proxies",
			trustedProxies: []string{},
			expectDirect:   true,
		},
		{
			name:           "empty proxy in list",
			trustedProxies: []string{""},
			expectDirect:   true,
		},
		{
			name:           "valid IPv4 address",
			trustedProxies: []string{"192.168.1.1"},
			expectDirect:   false,
		},
		{
			name:           "valid IPv4 CIDR",
			trustedProxies: []string{"192.168.1.0/24"},
			expectDirect:   false,
		},
		{
			name:           "valid IPv6 address",
			trustedProxies: []string{"2001:db8::1"},
			expectDirect:   false,
		},
		{
			name:           "invalid proxy",
			trustedProxies: []string{"invalid-proxy"},
			expectDirect:   true,
		},
		{
			name:           "mixed valid and invalid",
			trustedProxies: []string{"192.168.1.1", "invalid-proxy"},
			expectDirect:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			configureTrustedProxies(e, tt.trustedProxies, nil)

			if e.IPExtractor == nil {
				t.Error("expected IPExtractor to be set")
			}
		})
	}
}

func TestShortenHandlerName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "short handler name",
			input:    "handler.GetUser",
			expected: "handler.GetUser",
		},
		{
			name:     "handler with slash",
			input:    "github.com/user/repo/handler.GetUser",
			expected: "user/repo/handler.GetUser",
		},
		{
			name:     "very long handler name",
			input:    strings.Repeat("a", 100),
			expected: strings.Repeat("a", 77) + "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shortenHandlerName(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

type mockRenderer struct{}

func (m *mockRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return nil
}
