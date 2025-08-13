package templates

import (
	"context"

	"github.com/tech-arch1tect/brx/config"
	"go.uber.org/fx"
)

func NewProvider() fx.Option {
	return fx.Options(
		fx.Provide(func(cfg *config.Config) *Service {
			return New(&cfg.Templates)
		}),
		fx.Invoke(func(lc fx.Lifecycle, svc *Service) {
			if svc == nil {
				return
			}

			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					return svc.LoadTemplates()
				},
			})
		}),
	)
}
