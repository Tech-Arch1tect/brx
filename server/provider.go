package server

import (
	"context"

	"github.com/tech-arch1tect/brx/services/logging"
	"github.com/tech-arch1tect/brx/services/templates"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type SSLConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

func NewProvider() fx.Option {
	return fx.Options(
		fx.Provide(New),
		fx.Invoke(func(params struct {
			fx.In
			Lifecycle    fx.Lifecycle
			Server       *Server
			Logger       *logging.Service
			TemplatesSvc *templates.Service `optional:"true"`
			SSLConfig    *SSLConfig         `optional:"true"`
		}) {
			if params.Logger != nil {
				params.Logger.Debug("configuring server middleware and lifecycle hooks")
			}

			if params.TemplatesSvc != nil {
				params.Server.SetRenderer(params.TemplatesSvc.Renderer())
				if params.Logger != nil {
					params.Logger.Debug("template renderer configured for server")
				}
			} else if params.Logger != nil {
				params.Logger.Debug("no template service available - skipping renderer setup")
			}

			params.Server.Echo().Use(logging.RequestLogger(params.Logger))
			if params.Logger != nil {
				params.Logger.Debug("request logging middleware configured")
			}

			params.Lifecycle.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					if params.Logger != nil {
						params.Logger.Info("server lifecycle - starting up")
					}

					params.Server.LogRoutes()

					if params.SSLConfig != nil && params.SSLConfig.Enabled {
						if params.Logger != nil {
							params.Logger.Info("SSL enabled - starting HTTPS server in background",
								zap.String("cert_file", params.SSLConfig.CertFile),
								zap.String("key_file", params.SSLConfig.KeyFile))
						}
						go params.Server.StartTLS(params.SSLConfig.CertFile, params.SSLConfig.KeyFile)
					} else {
						if params.Logger != nil {
							params.Logger.Info("SSL disabled - starting HTTP server in background")
						}
						go params.Server.Start()
					}

					if params.Logger != nil {
						params.Logger.Info("server startup completed successfully")
					}
					return nil
				},
				OnStop: func(ctx context.Context) error {
					if params.Logger != nil {
						params.Logger.Info("server lifecycle - shutting down gracefully")
					}

					err := params.Server.Shutdown(ctx)
					if err != nil {
						if params.Logger != nil {
							params.Logger.Error("server shutdown failed", zap.Error(err))
						}
						return err
					}

					if params.Logger != nil {
						params.Logger.Info("server shutdown completed successfully")
					}
					return nil
				},
			})
		}),
	)
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.logger != nil {
		s.logger.Debug("initiating Echo server shutdown")
	}

	err := s.echo.Shutdown(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Echo server shutdown failed", zap.Error(err))
		}
		return err
	}

	if s.logger != nil {
		s.logger.Debug("Echo server shutdown completed")
	}
	return nil
}
