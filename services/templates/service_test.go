package templates

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/services/logging"
)

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
			Enabled:   true,
			Dir:       "templates",
			Extension: ".html",
		}

		service := New(cfg, nil)
		require.NotNil(t, service)
		assert.Equal(t, cfg, service.config)
		assert.Nil(t, service.logger)
		assert.Nil(t, service.templates)
	})

	t.Run("with logger", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Dir:         "templates",
			Extension:   ".gohtml",
			Development: true,
		}
		logger := newTestLogger()

		service := New(cfg, logger)
		require.NotNil(t, service)
		assert.Equal(t, cfg, service.config)
		assert.Equal(t, logger, service.logger)
	})
}

func TestService_LoadTemplates(t *testing.T) {
	t.Run("successful template loading", func(t *testing.T) {

		tempDir := t.TempDir()
		templatePath := filepath.Join(tempDir, "test.html")
		templateContent := `<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
</head>
<body>
    <h1>{{.Message}}</h1>
</body>
</html>`
		err := os.WriteFile(templatePath, []byte(templateContent), 0644)
		require.NoError(t, err)

		cfg := &Config{
			Enabled:   true,
			Dir:       tempDir,
			Extension: ".html",
		}
		service := New(cfg, nil)

		err = service.LoadTemplates()
		require.NoError(t, err)
		assert.NotNil(t, service.templates)
	})

	t.Run("template loading with logger", func(t *testing.T) {

		tempDir := t.TempDir()

		template1 := filepath.Join(tempDir, "index.gohtml")
		content1 := `<h1>{{.Title}}</h1>`
		err := os.WriteFile(template1, []byte(content1), 0644)
		require.NoError(t, err)

		template2 := filepath.Join(tempDir, "about.gohtml")
		content2 := `<p>{{.Content}}</p>`
		err = os.WriteFile(template2, []byte(content2), 0644)
		require.NoError(t, err)

		cfg := &Config{
			Enabled:     true,
			Dir:         tempDir,
			Extension:   ".gohtml",
			Development: false,
		}
		logger := newTestLogger()
		service := New(cfg, logger)

		err = service.LoadTemplates()
		require.NoError(t, err)
		assert.NotNil(t, service.templates)
		assert.Len(t, service.templates.Templates(), 2)
	})

	t.Run("invalid template pattern", func(t *testing.T) {
		cfg := &Config{
			Enabled:   true,
			Dir:       "/nonexistent/directory",
			Extension: ".html",
		}
		service := New(cfg, nil)

		err := service.LoadTemplates()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "pattern matches no files")
	})

	t.Run("invalid template syntax", func(t *testing.T) {

		tempDir := t.TempDir()
		templatePath := filepath.Join(tempDir, "invalid.html")
		invalidContent := `<html><body>{{.Title</body></html>`
		err := os.WriteFile(templatePath, []byte(invalidContent), 0644)
		require.NoError(t, err)

		cfg := &Config{
			Enabled:   true,
			Dir:       tempDir,
			Extension: ".html",
		}
		logger := newTestLogger()
		service := New(cfg, logger)

		err = service.LoadTemplates()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bad character")
	})
}

func TestService_Renderer(t *testing.T) {
	tempDir := t.TempDir()
	templatePath := filepath.Join(tempDir, "test.html")
	templateContent := `<h1>{{.Message}}</h1>`
	err := os.WriteFile(templatePath, []byte(templateContent), 0644)
	require.NoError(t, err)

	cfg := &Config{
		Enabled:   true,
		Dir:       tempDir,
		Extension: ".html",
	}

	t.Run("renderer creation", func(t *testing.T) {
		service := New(cfg, nil)
		err := service.LoadTemplates()
		require.NoError(t, err)

		renderer := service.Renderer()
		require.NotNil(t, renderer)
		assert.Equal(t, service.templates, renderer.templates)
		assert.Equal(t, service.config, renderer.config)
		assert.Equal(t, service.logger, renderer.logger)
	})

	t.Run("renderer creation with logger", func(t *testing.T) {
		logger := newTestLogger()
		service := New(cfg, logger)
		err := service.LoadTemplates()
		require.NoError(t, err)

		renderer := service.Renderer()
		require.NotNil(t, renderer)
		assert.Equal(t, logger, renderer.logger)
	})
}

func TestRenderer_Render(t *testing.T) {

	tempDir := t.TempDir()
	templatePath := filepath.Join(tempDir, "test.html")
	templateContent := `<h1>{{.Message}}</h1><p>{{.Count}}</p>`
	err := os.WriteFile(templatePath, []byte(templateContent), 0644)
	require.NoError(t, err)

	t.Run("successful rendering in production mode", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Dir:         tempDir,
			Extension:   ".html",
			Development: false,
		}
		service := New(cfg, nil)
		err := service.LoadTemplates()
		require.NoError(t, err)

		renderer := service.Renderer()

		var buf bytes.Buffer
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		data := map[string]interface{}{
			"Message": "Hello World",
			"Count":   42,
		}

		err = renderer.Render(&buf, "test.html", data, c)
		require.NoError(t, err)

		result := buf.String()
		assert.Contains(t, result, "Hello World")
		assert.Contains(t, result, "42")
	})

	t.Run("successful rendering in development mode", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Dir:         tempDir,
			Extension:   ".html",
			Development: true,
		}
		logger := newTestLogger()
		service := New(cfg, logger)

		renderer := service.Renderer()

		var buf bytes.Buffer
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		data := map[string]interface{}{
			"Message": "Dev Mode",
			"Count":   123,
		}

		err = renderer.Render(&buf, "test.html", data, c)
		require.NoError(t, err)

		result := buf.String()
		assert.Contains(t, result, "Dev Mode")
		assert.Contains(t, result, "123")
	})

	t.Run("template not found in production mode", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Dir:         tempDir,
			Extension:   ".html",
			Development: false,
		}
		service := New(cfg, nil)
		err := service.LoadTemplates()
		require.NoError(t, err)

		renderer := service.Renderer()

		var buf bytes.Buffer
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = renderer.Render(&buf, "nonexistent.html", nil, c)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is undefined")
	})

	t.Run("template reload failure in development mode", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Dir:         "/nonexistent/directory",
			Extension:   ".html",
			Development: true,
		}
		logger := newTestLogger()
		service := New(cfg, logger)

		renderer := service.Renderer()

		var buf bytes.Buffer
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = renderer.Render(&buf, "test.html", nil, c)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "pattern matches no files")
	})

	t.Run("template execution with invalid data", func(t *testing.T) {

		tempDir := t.TempDir()
		templatePath := filepath.Join(tempDir, "method.html")
		templateContent := `{{.User.NonExistentMethod}}`
		err := os.WriteFile(templatePath, []byte(templateContent), 0644)
		require.NoError(t, err)

		cfg := &Config{
			Enabled:     true,
			Dir:         tempDir,
			Extension:   ".html",
			Development: false,
		}
		service := New(cfg, nil)
		err = service.LoadTemplates()
		require.NoError(t, err)

		renderer := service.Renderer()

		var buf bytes.Buffer
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		data := map[string]interface{}{
			"User": nil,
		}

		err = renderer.Render(&buf, "method.html", data, c)
		require.Error(t, err)
		assert.Contains(t, strings.ToLower(err.Error()), "nil pointer")
	})

	t.Run("rendering with nil templates in production mode", func(t *testing.T) {
		cfg := &Config{
			Enabled:     true,
			Dir:         tempDir,
			Extension:   ".html",
			Development: false,
		}
		service := New(cfg, nil)

		renderer := service.Renderer()

		var buf bytes.Buffer
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		assert.Panics(t, func() {
			renderer.Render(&buf, "test.html", nil, c)
		})
	})
}

func TestRenderer_RenderWithComplexData(t *testing.T) {

	tempDir := t.TempDir()
	templatePath := filepath.Join(tempDir, "complex.html")
	templateContent := `
<h1>{{.Title}}</h1>
{{if .ShowUsers}}
<ul>
{{range .Users}}
<li>{{.Name}} ({{.Role}})</li>
{{end}}
</ul>
{{else}}
<p>No users to display</p>
{{end}}
<p>Total: {{len .Users}}</p>`
	err := os.WriteFile(templatePath, []byte(templateContent), 0644)
	require.NoError(t, err)

	cfg := &Config{
		Enabled:     true,
		Dir:         tempDir,
		Extension:   ".html",
		Development: false,
	}
	logger := newTestLogger()
	service := New(cfg, logger)
	err = service.LoadTemplates()
	require.NoError(t, err)

	renderer := service.Renderer()

	t.Run("rendering with complex data structure", func(t *testing.T) {
		var buf bytes.Buffer
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		data := map[string]interface{}{
			"Title":     "User Management",
			"ShowUsers": true,
			"Users": []map[string]string{
				{"Name": "Alice", "Role": "Admin"},
				{"Name": "Bob", "Role": "User"},
				{"Name": "Charlie", "Role": "Manager"},
			},
		}

		err = renderer.Render(&buf, "complex.html", data, c)
		require.NoError(t, err)

		result := buf.String()
		assert.Contains(t, result, "User Management")
		assert.Contains(t, result, "Alice")
		assert.Contains(t, result, "Admin")
		assert.Contains(t, result, "Bob")
		assert.Contains(t, result, "User")
		assert.Contains(t, result, "Charlie")
		assert.Contains(t, result, "Manager")
		assert.Contains(t, result, "Total: 3")
	})

	t.Run("rendering with ShowUsers false", func(t *testing.T) {
		var buf bytes.Buffer
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		data := map[string]interface{}{
			"Title":     "User Management",
			"ShowUsers": false,
			"Users":     []map[string]string{},
		}

		err = renderer.Render(&buf, "complex.html", data, c)
		require.NoError(t, err)

		result := buf.String()
		assert.Contains(t, result, "User Management")
		assert.Contains(t, result, "No users to display")
		assert.Contains(t, result, "Total: 0")
	})
}
