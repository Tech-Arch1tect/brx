package templates

import (
	"html/template"
	"io"
	"path/filepath"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/zap"
)

type Service struct {
	config    *Config
	templates *template.Template
	logger    *logging.Service
}

type Renderer struct {
	templates *template.Template
	config    *Config
	logger    *logging.Service
}

func New(cfg *Config, logger *logging.Service) *Service {
	if !cfg.Enabled {
		if logger != nil {
			logger.Debug("templates service disabled in configuration")
		}
		return nil
	}

	if logger != nil {
		logger.Info("initializing templates service",
			zap.String("templates_dir", cfg.Dir),
			zap.String("extension", cfg.Extension),
			zap.Bool("development_mode", cfg.Development))
	}

	return &Service{
		config: cfg,
		logger: logger,
	}
}

func (s *Service) LoadTemplates() error {
	pattern := filepath.Join(s.config.Dir, "*"+s.config.Extension)

	if s.logger != nil {
		s.logger.Info("loading templates",
			zap.String("pattern", pattern),
			zap.Bool("development_mode", s.config.Development))
	}

	startTime := time.Now()
	tmpl, err := template.ParseGlob(pattern)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to load templates",
				zap.Error(err),
				zap.String("pattern", pattern),
				zap.Duration("load_duration", time.Since(startTime)))
		}
		return err
	}

	s.templates = tmpl

	// Count loaded templates
	templateCount := 0
	if tmpl != nil {
		templateCount = len(tmpl.Templates())
	}

	if s.logger != nil {
		s.logger.Info("templates loaded successfully",
			zap.Int("template_count", templateCount),
			zap.String("pattern", pattern),
			zap.Duration("load_duration", time.Since(startTime)))
	}

	return nil
}

func (s *Service) Renderer() *Renderer {
	if s.logger != nil {
		s.logger.Debug("creating template renderer",
			zap.Bool("development_mode", s.config.Development))
	}

	return &Renderer{
		templates: s.templates,
		config:    s.config,
		logger:    s.logger,
	}
}

func (r *Renderer) Render(w io.Writer, name string, data any, c echo.Context) error {
	if r.logger != nil {
		r.logger.Debug("rendering template",
			zap.String("template_name", name),
			zap.Bool("development_mode", r.config.Development))
	}

	startTime := time.Now()

	if r.config.Development {
		if r.logger != nil {
			r.logger.Debug("development mode - reloading templates for render")
		}

		pattern := filepath.Join(r.config.Dir, "*"+r.config.Extension)
		tmpl, err := template.ParseGlob(pattern)
		if err != nil {
			if r.logger != nil {
				r.logger.Error("failed to reload templates in development mode",
					zap.Error(err),
					zap.String("template_name", name),
					zap.String("pattern", pattern))
			}
			return err
		}

		err = tmpl.ExecuteTemplate(w, name, data)
		if err != nil {
			if r.logger != nil {
				r.logger.Error("template rendering failed in development mode",
					zap.Error(err),
					zap.String("template_name", name),
					zap.Duration("render_duration", time.Since(startTime)))
			}
			return err
		}

		if r.logger != nil {
			r.logger.Debug("template rendered successfully in development mode",
				zap.String("template_name", name),
				zap.Duration("render_duration", time.Since(startTime)))
		}

		return nil
	}

	err := r.templates.ExecuteTemplate(w, name, data)
	if err != nil {
		if r.logger != nil {
			r.logger.Error("template rendering failed",
				zap.Error(err),
				zap.String("template_name", name),
				zap.Duration("render_duration", time.Since(startTime)))
		}
		return err
	}

	if r.logger != nil {
		r.logger.Debug("template rendered successfully",
			zap.String("template_name", name),
			zap.Duration("render_duration", time.Since(startTime)))
	}

	return nil
}
