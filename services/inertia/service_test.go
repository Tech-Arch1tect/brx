package inertia

import (
	"embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v4"
	gonertia "github.com/romsar/gonertia/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/services/logging"
)

//go:embed testdata
var testFS embed.FS

func newTestLogger() *logging.Service {
	config := logging.Config{
		Level:      logging.Debug,
		Format:     "console",
		OutputPath: "stdout",
	}
	logger, _ := logging.NewService(config)
	return logger
}

func TestNew(t *testing.T) {
	t.Run("disabled service returns nil", func(t *testing.T) {
		cfg := &Config{
			Enabled: false,
		}

		service := New(cfg, nil)
		assert.Nil(t, service)
	})

	t.Run("enabled service returns instance", func(t *testing.T) {
		cfg := &Config{
			Enabled:    true,
			SSREnabled: false,
			Version:    "test-version",
		}

		service := New(cfg, nil)
		require.NotNil(t, service)
		assert.Equal(t, cfg, service.config)
		assert.Nil(t, service.logger)
		assert.Nil(t, service.inertia)
	})

	t.Run("with logger", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			SSREnabled:  true,
			SSRURL:      "http://localhost:13714",
			Version:     "v1.0.0",
			Development: true,
		}
		logger := newTestLogger()

		service := New(cfg, logger)
		require.NotNil(t, service)
		assert.Equal(t, cfg, service.config)
		assert.Equal(t, logger, service.logger)
	})
}

func TestService_InitializeFromFile(t *testing.T) {

	tempDir := t.TempDir()
	templatePath := filepath.Join(tempDir, "app.html")
	templateContent := `<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
</head>
<body>
    <div id="app" data-page="{{.page}}"></div>
</body>
</html>`
	err := os.WriteFile(templatePath, []byte(templateContent), 0644)
	require.NoError(t, err)

	t.Run("successful initialization", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
			Version: "test-version",
		}
		logger := newTestLogger()
		service := New(cfg, logger)

		err := service.InitializeFromFile(templatePath)
		require.NoError(t, err)
		assert.NotNil(t, service.inertia)
	})

	t.Run("with SSR enabled", func(t *testing.T) {
		cfg := &Config{
			Enabled:    true,
			SSREnabled: true,
			SSRURL:     "http://localhost:13714",
		}
		service := New(cfg, nil)

		err := service.InitializeFromFile(templatePath)
		require.NoError(t, err)
		assert.NotNil(t, service.inertia)
	})

	t.Run("with SSR enabled but no URL", func(t *testing.T) {
		cfg := &Config{
			Enabled:    true,
			SSREnabled: true,
		}
		service := New(cfg, nil)

		err := service.InitializeFromFile(templatePath)
		require.NoError(t, err)
		assert.NotNil(t, service.inertia)
	})

	t.Run("nonexistent template file", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
		}
		service := New(cfg, nil)

		err := service.InitializeFromFile("/nonexistent/template.html")
		require.Error(t, err)
		assert.Nil(t, service.inertia)
	})
}

func TestService_InitializeFromFS(t *testing.T) {

	tempDir := t.TempDir()
	testdataDir := filepath.Join(tempDir, "testdata")
	err := os.MkdirAll(testdataDir, 0755)
	require.NoError(t, err)

	templatePath := filepath.Join(testdataDir, "app.html")
	templateContent := `<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
</head>
<body>
    <div id="app" data-page="{{.page}}"></div>
</body>
</html>`
	err = os.WriteFile(templatePath, []byte(templateContent), 0644)
	require.NoError(t, err)

	t.Run("successful initialization", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
			Version: "test-version",
		}
		service := New(cfg, nil)

		err := service.InitializeFromFS(testFS, "testdata/app.html")

		assert.NoError(t, err)
		assert.NotNil(t, service.inertia)
	})

	t.Run("with SSR configuration", func(t *testing.T) {
		cfg := &Config{
			Enabled:    true,
			SSREnabled: true,
			SSRURL:     "http://localhost:13714",
		}
		service := New(cfg, nil)

		err := service.InitializeFromFS(testFS, "testdata/app.html")

		assert.NoError(t, err)
		assert.NotNil(t, service.inertia)
	})
}

func TestService_Instance(t *testing.T) {
	cfg := &Config{
		Enabled: true,
	}
	service := New(cfg, nil)

	assert.Nil(t, service.Instance())

	service.inertia = &gonertia.Inertia{}
	assert.NotNil(t, service.Instance())
}

func TestService_Render(t *testing.T) {
	t.Run("render without initialization fails", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
		}
		service := New(cfg, nil)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := service.Render(c, "TestComponent", gonertia.Props{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "inertia instance is nil")
	})
}

func TestService_Redirect(t *testing.T) {
	cfg := &Config{
		Enabled: true,
	}
	service := New(cfg, nil)

	e := echo.New()

	t.Run("GET request redirect with nil inertia panics", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		assert.Panics(t, func() {
			service.Redirect(c, "/home")
		})
	})

	testCases := []struct {
		method string
		name   string
	}{
		{http.MethodPut, "PUT request"},
		{http.MethodPatch, "PATCH request"},
		{http.MethodDelete, "DELETE request"},
	}

	for _, tc := range testCases {
		t.Run(tc.name+" uses 303 redirect", func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := service.Redirect(c, "/home")
			require.NoError(t, err)
			assert.Equal(t, 303, rec.Code)
			assert.Equal(t, "/home", rec.Header().Get("Location"))
		})
	}
}

func TestService_Back(t *testing.T) {
	cfg := &Config{
		Enabled: true,
	}
	service := New(cfg, nil)

	e := echo.New()

	t.Run("GET request back with nil inertia panics", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Referer", "/previous")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		assert.Panics(t, func() {
			service.Back(c)
		})
	})

	testCases := []struct {
		method string
		name   string
	}{
		{http.MethodPut, "PUT request"},
		{http.MethodPatch, "PATCH request"},
		{http.MethodDelete, "DELETE request"},
	}

	for _, tc := range testCases {
		t.Run(tc.name+" with referer uses 303 redirect", func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/", nil)
			req.Header.Set("Referer", "/previous")
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := service.Back(c)
			require.NoError(t, err)
			assert.Equal(t, 303, rec.Code)
			assert.Equal(t, "/previous", rec.Header().Get("Location"))
		})

		t.Run(tc.name+" without referer panics", func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			assert.Panics(t, func() {
				service.Back(c)
			})
		})
	}
}

func TestService_ApplyMiddlewareToGroup(t *testing.T) {
	t.Run("without initialized inertia", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
		}
		service := New(cfg, nil)

		e := echo.New()
		group := e.Group("/test")

		service.ApplyMiddlewareToGroup(group, nil)
	})

	t.Run("with user provider", func(t *testing.T) {
		cfg := &Config{
			Enabled: true,
		}
		service := New(cfg, nil)
		service.inertia = &gonertia.Inertia{}

		e := echo.New()
		group := e.Group("/test")

		service.ApplyMiddlewareToGroup(group, nil)
	})
}

func TestService_Location(t *testing.T) {
	cfg := &Config{
		Enabled: true,
	}
	service := New(cfg, nil)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	assert.Panics(t, func() {
		service.Location(c, "http://example.com")
	})
}

func TestService_ShareProp(t *testing.T) {
	cfg := &Config{
		Enabled: true,
	}
	service := New(cfg, nil)

	assert.Panics(t, func() {
		service.ShareProp("test", "value")
	})
}

func TestService_ShareTemplateData(t *testing.T) {
	cfg := &Config{
		Enabled: true,
	}
	service := New(cfg, nil)

	assert.Panics(t, func() {
		service.ShareTemplateData("test", "value")
	})
}

func TestService_ShareTemplateFunc(t *testing.T) {
	cfg := &Config{
		Enabled: true,
	}
	service := New(cfg, nil)

	assert.Panics(t, func() {
		service.ShareTemplateFunc("test", func() string { return "test" })
	})
}

func TestService_LoadManifest(t *testing.T) {
	t.Run("development mode skips loading", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Development: true,
		}
		service := New(cfg, nil)

		err := service.LoadManifest("/nonexistent/manifest.json")
		require.NoError(t, err)
		assert.Nil(t, service.manifest)
	})

	t.Run("production mode loads manifest", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Development: false,
		}
		service := New(cfg, nil)

		tempDir := t.TempDir()
		manifestPath := filepath.Join(tempDir, "manifest.json")
		manifest := ViteManifest{
			"src/main.ts": ViteManifestEntry{
				File:    "assets/main.abc123.js",
				Src:     "src/main.ts",
				IsEntry: true,
				CSS:     []string{"assets/main.abc123.css"},
			},
		}

		data, err := json.Marshal(manifest)
		require.NoError(t, err)
		err = os.WriteFile(manifestPath, data, 0644)
		require.NoError(t, err)

		err = service.LoadManifest(manifestPath)
		require.NoError(t, err)
		assert.NotNil(t, service.manifest)
		assert.Len(t, *service.manifest, 1)
	})

	t.Run("nonexistent manifest file", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Development: false,
		}
		service := New(cfg, nil)

		err := service.LoadManifest("/nonexistent/manifest.json")
		require.Error(t, err)
		assert.Nil(t, service.manifest)
	})

	t.Run("invalid JSON manifest", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Development: false,
		}
		service := New(cfg, nil)

		tempDir := t.TempDir()
		manifestPath := filepath.Join(tempDir, "manifest.json")
		err := os.WriteFile(manifestPath, []byte("invalid json"), 0644)
		require.NoError(t, err)

		err = service.LoadManifest(manifestPath)
		require.Error(t, err)
		assert.Nil(t, service.manifest)
	})
}

func TestService_getAssets(t *testing.T) {
	t.Run("development mode returns empty assets", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Development: true,
		}
		service := New(cfg, nil)

		css, js, isDev := service.getAssets()
		assert.Empty(t, css)
		assert.Empty(t, js)
		assert.True(t, isDev)
	})

	t.Run("production mode without manifest", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Development: false,
		}
		service := New(cfg, nil)

		css, js, isDev := service.getAssets()
		assert.Empty(t, css)
		assert.Empty(t, js)
		assert.False(t, isDev)
	})

	t.Run("production mode with manifest", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Development: false,
		}
		service := New(cfg, nil)

		manifest := ViteManifest{
			"src/main.ts": ViteManifestEntry{
				File:    "assets/main.abc123.js",
				Src:     "src/main.ts",
				IsEntry: true,
				CSS:     []string{"assets/main.abc123.css", "assets/styles.def456.css"},
			},
			"src/admin.ts": ViteManifestEntry{
				File:    "assets/admin.xyz789.js",
				Src:     "src/admin.ts",
				IsEntry: true,
			},
			"src/utils.ts": ViteManifestEntry{
				File:    "assets/utils.ghi012.js",
				Src:     "src/utils.ts",
				IsEntry: false,
			},
		}
		service.manifest = &manifest

		css, js, isDev := service.getAssets()
		assert.False(t, isDev)

		expectedCSS := []string{
			"/build/assets/main.abc123.css",
			"/build/assets/styles.def456.css",
		}
		expectedJS := []string{
			"/build/assets/main.abc123.js",
			"/build/assets/admin.xyz789.js",
		}

		assert.ElementsMatch(t, expectedCSS, css)
		assert.ElementsMatch(t, expectedJS, js)
	})
}

func TestService_ShareAssetData(t *testing.T) {
	t.Run("development mode", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Development: true,
		}
		service := New(cfg, nil)

		assert.Panics(t, func() {
			service.ShareAssetData()
		})
	})

	t.Run("production mode with manifest", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Development: false,
		}
		service := New(cfg, nil)

		manifest := ViteManifest{
			"src/main.ts": ViteManifestEntry{
				File:    "assets/main.abc123.js",
				Src:     "src/main.ts",
				IsEntry: true,
				CSS:     []string{"assets/main.abc123.css"},
			},
		}
		service.manifest = &manifest

		assert.Panics(t, func() {
			service.ShareAssetData()
		})
	})
}

func TestViteManifestEntry(t *testing.T) {
	entry := ViteManifestEntry{
		File:    "assets/main.abc123.js",
		Src:     "src/main.ts",
		IsEntry: true,
		CSS:     []string{"assets/main.abc123.css"},
		Assets:  []string{"assets/logo.png"},
	}

	assert.Equal(t, "assets/main.abc123.js", entry.File)
	assert.Equal(t, "src/main.ts", entry.Src)
	assert.True(t, entry.IsEntry)
	assert.Equal(t, []string{"assets/main.abc123.css"}, entry.CSS)
	assert.Equal(t, []string{"assets/logo.png"}, entry.Assets)
}
