package app

import (
	"context"
	"log"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/internal/options"
	"github.com/tech-arch1tect/brx/server"
	"github.com/tech-arch1tect/brx/services/inertia"
	"github.com/tech-arch1tect/brx/services/templates"
	"go.uber.org/fx"
)

type App struct {
	server     *server.Server
	fx         *fx.App
	inertiaSvc *inertia.Service
}

func New(opts ...options.Option) *App {
	appOpts := &options.Options{}

	for _, opt := range opts {
		opt(appOpts)
	}

	var cfg *config.Config
	if appOpts.Config != nil {
		cfg = appOpts.Config
	} else {
		cfg = &config.Config{}
		if err := config.LoadConfig(cfg); err != nil {
			panic(err)
		}
	}

	srv := server.New(cfg)

	var templateSvc *templates.Service
	if appOpts.EnableTemplates {
		templateSvc = templates.New(&cfg.Templates)
		if templateSvc != nil {
			srv.SetRenderer(templateSvc.Renderer())
		}
	}

	var inertiaSvc *inertia.Service
	if appOpts.EnableInertia {
		inertiaSvc = inertia.New(&cfg.Inertia)
	}

	var fxOptions []fx.Option
	fxOptions = append(fxOptions, fx.Supply(cfg))
	fxOptions = append(fxOptions, fx.Supply(srv))

	if templateSvc != nil {
		fxOptions = append(fxOptions, fx.Supply(templateSvc))
		fxOptions = append(fxOptions, fx.Invoke(func(lc fx.Lifecycle, svc *templates.Service) {
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					return svc.LoadTemplates()
				},
			})
		}))
	}

	if inertiaSvc != nil {
		fxOptions = append(fxOptions, fx.Supply(inertiaSvc))
		fxOptions = append(fxOptions, fx.Invoke(func(lc fx.Lifecycle, svc *inertia.Service, cfg *config.Config) {
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					rootViewPath := cfg.Inertia.RootView
					if rootViewPath == "" {
						rootViewPath = "app.html"
					}

					if err := svc.InitializeFromFile(rootViewPath); err != nil {
						return err
					}

					if !cfg.Inertia.Development {
						if err := svc.LoadManifest("public/build/.vite/manifest.json"); err != nil {
							log.Printf("Warning: Could not load Vite manifest: %v", err)
						}
					}

					svc.ShareAssetData()
					return nil
				},
			})
		}))
	}

	fxOptions = append(fxOptions, fx.Invoke(func(lc fx.Lifecycle, srv *server.Server) {
		lc.Append(fx.Hook{
			OnStart: func(ctx context.Context) error {
				go srv.Start()
				return nil
			},
			OnStop: func(ctx context.Context) error {
				return srv.Shutdown(ctx)
			},
		})
	}))

	fxOptions = append(fxOptions, fx.NopLogger)

	fxApp := fx.New(fxOptions...)

	return &App{
		server:     srv,
		fx:         fxApp,
		inertiaSvc: inertiaSvc,
	}
}

func (a *App) Start() {
	if err := a.fx.Start(context.Background()); err != nil {
		log.Fatalf("Failed to start application: %v", err)
	}

	<-a.fx.Done()
}

func (a *App) Stop() {
	if err := a.fx.Stop(context.Background()); err != nil {
		log.Printf("Failed to stop application gracefully: %v", err)
	}
}

func (a *App) Get(path string, handler echo.HandlerFunc) {
	a.server.Get(path, handler)
}

func (a *App) Post(path string, handler echo.HandlerFunc) {
	a.server.Post(path, handler)
}

func (a *App) Put(path string, handler echo.HandlerFunc) {
	a.server.Put(path, handler)
}

func (a *App) Delete(path string, handler echo.HandlerFunc) {
	a.server.Delete(path, handler)
}

func (a *App) Patch(path string, handler echo.HandlerFunc) {
	a.server.Patch(path, handler)
}

func (a *App) InertiaService() *inertia.Service {
	return a.inertiaSvc
}
