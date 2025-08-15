package mail

import (
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/auth"
	"go.uber.org/fx"
)

func ProvideMailService(cfg *config.Config) (*Service, error) {
	return NewService(&cfg.Mail)
}

func ProvideMailAsInterface(svc *Service) auth.MailService {
	return svc
}

var Module = fx.Options(
	fx.Provide(ProvideMailService),
	fx.Provide(ProvideMailAsInterface),
)
