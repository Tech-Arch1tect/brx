package logging

import (
	"github.com/tech-arch1tect/brx/config"
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Provide(NewLoggingService),
)

func NewLoggingService(cfg *config.Config) (*Service, error) {
	loggingConfig := Config{
		Level:      LogLevel(cfg.Log.Level),
		Format:     cfg.Log.Format,
		OutputPath: cfg.Log.Output,
	}

	return NewService(loggingConfig)
}
