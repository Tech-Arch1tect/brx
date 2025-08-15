package mail

import (
	"github.com/tech-arch1tect/brx/config"
	"go.uber.org/fx"
)

func ProvideMailService(cfg *config.Config) (*Service, error) {
	return NewService(&cfg.Mail)
}

var Module = fx.Options(
	fx.Provide(ProvideMailService),
)
