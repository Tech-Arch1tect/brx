package server

import (
	"context"

	"github.com/tech-arch1tect/brx/internal/options"
	"github.com/tech-arch1tect/brx/services/logging"
	"github.com/tech-arch1tect/brx/services/templates"
	"go.uber.org/fx"
)

func NewProvider() fx.Option {
	return fx.Options(
		fx.Provide(New),
		fx.Invoke(func(params struct {
			fx.In
			Lifecycle    fx.Lifecycle
			Server       *Server
			Logger       *logging.Service
			TemplatesSvc *templates.Service `optional:"true"`
			Options      *options.Options
		}) {
			if params.TemplatesSvc != nil {
				params.Server.SetRenderer(params.TemplatesSvc.Renderer())
			}

			params.Server.Echo().Use(logging.RequestLogger(params.Logger))

			params.Lifecycle.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					params.Server.LogRoutes()

					if params.Options.EnableSSL {
						go params.Server.StartTLS(params.Options.SSLCertFile, params.Options.SSLKeyFile)
					} else {
						go params.Server.Start()
					}
					return nil
				},
				OnStop: func(ctx context.Context) error {
					return params.Server.Shutdown(ctx)
				},
			})
		}),
	)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.echo.Shutdown(ctx)
}
