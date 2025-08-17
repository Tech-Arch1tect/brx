package totp

import (
	"github.com/tech-arch1tect/brx/config"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

func NewProvider(cfg *config.Config, db *gorm.DB) *Service {
	return NewService(cfg, db)
}

var Module = fx.Options(
	fx.Provide(NewProvider),
)
