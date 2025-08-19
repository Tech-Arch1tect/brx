package jwt

import (
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/fx"
)

func NewJWTService(cfg *config.Config, logger *logging.Service) *Service {
	return NewService(cfg, logger)
}

var Options = fx.Options(
	fx.Provide(NewJWTService),
)
