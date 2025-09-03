package templates

import (
	"context"

	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

func NewProvider() fx.Option {
	return fx.Options(
		fx.Provide(func(cfg *config.Config, logger *logging.Service) *Service {
			return New(&cfg.Templates, logger)
		}),
		fx.Invoke(func(lc fx.Lifecycle, svc *Service, logger *logging.Service) {
			if svc == nil {
				if logger != nil {
					logger.Debug("templates service not available - skipping lifecycle hooks")
				}
				return
			}

			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					if logger != nil {
						logger.Info("starting templates service - loading templates")
					}

					err := svc.LoadTemplates()
					if err != nil {
						if logger != nil {
							logger.Error("failed to start templates service", zap.Error(err))
						}
						return err
					}

					if logger != nil {
						logger.Info("templates service started successfully")
					}
					return nil
				},
			})
		}),
	)
}
