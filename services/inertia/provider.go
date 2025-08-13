package inertia

import (
	"context"
	"path/filepath"

	"github.com/tech-arch1tect/brx/config"
	"go.uber.org/fx"
)

func NewProvider() fx.Option {
	return fx.Options(
		fx.Provide(func(cfg *config.Config) *Service {
			return New(&cfg.Inertia)
		}),
		fx.Invoke(func(lc fx.Lifecycle, svc *Service, cfg *config.Config) {
			if svc == nil {
				return
			}

			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					rootViewPath := cfg.Inertia.RootView
					if !filepath.IsAbs(rootViewPath) {
						rootViewPath = filepath.Join("resources/views", rootViewPath)
					}
					return svc.InitializeFromFile(rootViewPath)
				},
			})
		}),
	)
}
