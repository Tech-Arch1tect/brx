package inertia

import (
	"context"
	"path/filepath"

	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

func NewProvider() fx.Option {
	return fx.Options(
		fx.Provide(func(cfg *config.Config, logger *logging.Service) *Service {
			return New(&cfg.Inertia, logger)
		}),
		fx.Invoke(func(lc fx.Lifecycle, svc *Service, cfg *config.Config, logger *logging.Service) {
			if svc == nil {
				if logger != nil {
					logger.Debug("Inertia service not available - skipping lifecycle hooks")
				}
				return
			}

			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					if logger != nil {
						logger.Info("starting Inertia service - initializing from file")
					}

					rootViewPath := cfg.Inertia.RootView
					if !filepath.IsAbs(rootViewPath) {
						rootViewPath = filepath.Join("resources/views", rootViewPath)
					}

					err := svc.InitializeFromFile(rootViewPath)
					if err != nil {
						if logger != nil {
							logger.Error("failed to start Inertia service",
								zap.Error(err),
								zap.String("root_view_path", rootViewPath))
						}
						return err
					}

					if logger != nil {
						logger.Info("Inertia service started successfully")
					}
					return nil
				},
			})
		}),
	)
}
