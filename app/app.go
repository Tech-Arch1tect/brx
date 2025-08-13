package app

import (
	"context"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/internal/options"
	"github.com/tech-arch1tect/brx/server"
	"go.uber.org/fx"
)

type App struct {
	server *server.Server
	fx     *fx.App
}

func New(opts ...options.Option) *App {
	appOpts := &options.Options{}

	for _, opt := range opts {
		opt(appOpts)
	}

	var fxOptions []fx.Option
	fxOptions = append(fxOptions, config.NewProvider(appOpts.Config))
	fxOptions = append(fxOptions, server.NewProvider())
	fxOptions = append(fxOptions, fx.NopLogger)

	var srv *server.Server
	fxOptions = append(fxOptions, fx.Populate(&srv))

	fxApp := fx.New(fxOptions...)

	return &App{
		server: srv,
		fx:     fxApp,
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

func (a *App) Get(path string, handler fiber.Handler) {
	a.server.Get(path, handler)
}

func (a *App) Post(path string, handler fiber.Handler) {
	a.server.Post(path, handler)
}

func (a *App) Put(path string, handler fiber.Handler) {
	a.server.Put(path, handler)
}

func (a *App) Delete(path string, handler fiber.Handler) {
	a.server.Delete(path, handler)
}

func (a *App) Patch(path string, handler fiber.Handler) {
	a.server.Patch(path, handler)
}
