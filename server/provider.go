package server

import (
	"context"

	"go.uber.org/fx"
)

func NewProvider() fx.Option {
	return fx.Options(
		fx.Provide(New),
		fx.Invoke(func(lc fx.Lifecycle, srv *Server) {
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					go srv.Start()
					return nil
				},
				OnStop: func(ctx context.Context) error {
					return srv.Shutdown(ctx)
				},
			})
		}),
	)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.fiber.ShutdownWithContext(ctx)
}
