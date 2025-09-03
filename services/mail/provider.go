package mail

import (
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/auth"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/fx"
)

func ProvideMailService(cfg *config.Config, logger *logging.Service) (*Service, error) {
	return NewService(&cfg.Mail, logger)
}

func ProvideMailAsInterface(svc *Service) auth.MailService {
	return svc
}

var Module = fx.Options(
	fx.Provide(ProvideMailService),
	fx.Provide(ProvideMailAsInterface),
)
