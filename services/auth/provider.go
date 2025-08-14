package auth

import (
	"github.com/tech-arch1tect/brx/config"
	"go.uber.org/fx"
)

func ProvideAuthService(cfg *config.Config) *Service {
	return NewService(&cfg.Auth)
}

var Module = fx.Options(
	fx.Provide(ProvideAuthService),
)
