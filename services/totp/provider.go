package totp

import (
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

func NewProvider(cfg *config.Config, db *gorm.DB, logger *logging.Service) *Service {
	return NewService(cfg, db, logger)
}

var Module = fx.Options(
	fx.Provide(NewProvider),
)
