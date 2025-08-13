package templates

import (
	"html/template"
	"io"
	"path/filepath"

	"github.com/labstack/echo/v4"
)

type Service struct {
	config    *Config
	templates *template.Template
}

type Renderer struct {
	templates *template.Template
	config    *Config
}

func New(cfg *Config) *Service {
	if !cfg.Enabled {
		return nil
	}

	return &Service{
		config: cfg,
	}
}

func (s *Service) LoadTemplates() error {
	pattern := filepath.Join(s.config.Dir, "*"+s.config.Extension)
	tmpl, err := template.ParseGlob(pattern)
	if err != nil {
		return err
	}

	s.templates = tmpl
	return nil
}

func (s *Service) Renderer() *Renderer {
	return &Renderer{
		templates: s.templates,
		config:    s.config,
	}
}

func (r *Renderer) Render(w io.Writer, name string, data any, c echo.Context) error {
	if r.config.Development {
		pattern := filepath.Join(r.config.Dir, "*"+r.config.Extension)
		tmpl, err := template.ParseGlob(pattern)
		if err != nil {
			return err
		}
		return tmpl.ExecuteTemplate(w, name, data)
	}

	return r.templates.ExecuteTemplate(w, name, data)
}
