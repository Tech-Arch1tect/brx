package brx

import (
	"github.com/tech-arch1tect/brx/app"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/internal/options"
)

type App = app.App

func New(opts ...options.Option) *App {
	return app.New(opts...)
}

func WithConfig(cfg *config.Config) options.Option {
	return options.WithConfig(cfg)
}
