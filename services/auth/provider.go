package auth

import (
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"github.com/tech-arch1tect/brx/session"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

func ProvideAuthService(cfg *config.Config, db *gorm.DB, logger *logging.Service) *Service {
	return NewService(cfg, db, logger)
}

type OptionalMailService struct {
	fx.In
	MailService MailService `optional:"true"`
}

func WireMailService(authSvc *Service, optMailSvc OptionalMailService) {
	if authSvc != nil && optMailSvc.MailService != nil {
		authSvc.SetMailService(optMailSvc.MailService)
	}
}

type OptionalSessionService struct {
	fx.In
	SessionService session.SessionService `optional:"true"`
}

func WireSessionInvalidator(authSvc *Service, opt OptionalSessionService) {
	if authSvc != nil && opt.SessionService != nil {
		authSvc.SetSessionInvalidator(opt.SessionService)
	}
}

type OptionalDB struct {
	fx.In
	DB *gorm.DB `optional:"true"`
}

func MigratePasswordResetTokens(optDB OptionalDB, cfg *config.Config) error {
	if cfg.Auth.PasswordResetEnabled && optDB.DB != nil {
		return optDB.DB.AutoMigrate(&PasswordResetToken{})
	}
	return nil
}

var Module = fx.Options(
	fx.Provide(ProvideAuthService),
	fx.Invoke(WireMailService),
	fx.Invoke(WireSessionInvalidator),
	fx.Invoke(MigratePasswordResetTokens),
)
