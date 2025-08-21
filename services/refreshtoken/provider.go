package refreshtoken

import (
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

func ProvideRefreshTokenService(db *gorm.DB, config *config.Config, logger *logging.Service) RefreshTokenService {
	service := NewService(db, config, logger)

	if config.RefreshToken.CleanupInterval > 0 {
		service.StartCleanupWorker()
	}

	return service
}

var Options = fx.Options(
	fx.Provide(ProvideRefreshTokenService),
)
