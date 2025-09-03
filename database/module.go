package database

import (
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

var Module = fx.Options(
	fx.Provide(ProvideDatabaseFx),
)

func ProvideDatabaseFx(cfg *config.Config, modelsOpt *ModelsOption, logger *logging.Service) (*gorm.DB, error) {
	return ProvideDatabase(*cfg, modelsOpt, logger)
}
