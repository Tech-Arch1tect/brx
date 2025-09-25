package app

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/server"
	"github.com/tech-arch1tect/brx/services/inertia"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

type App struct {
	fx         *fx.App
	config     *config.Config
	logger     *logging.Service
	services   *ServiceContainer
	inertiaSvc *inertia.Service
	db         *gorm.DB
	server     *server.Server
}

func (a *App) Start() error {
	ctx := context.Background()
	if err := a.fx.Start(ctx); err != nil {
		return err
	}
	return nil
}

func (a *App) StartTest() error {
	return a.fx.Start(context.Background())
}

func (a *App) Run() {
	if err := a.Start(); err != nil {
		log.Fatalf("Failed to start application: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	if a.logger != nil {
		a.logger.Info("Received shutdown signal, stopping gracefully...")
	} else {
		log.Printf("Received signal %v, shutting down gracefully...", sig)
	}

	a.Stop()
}

func (a *App) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := a.fx.Stop(ctx); err != nil {
		if a.logger != nil {
			a.logger.Error("Failed to stop application gracefully")
		} else {
			log.Printf("Failed to stop application gracefully: %v", err)
		}
	}
}

func (a *App) StopTest() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := a.fx.Stop(ctx); err != nil {
		if a.logger != nil {
			a.logger.Error("Failed to stop test application")
		} else {
			log.Printf("Failed to stop test application: %v", err)
		}
	}
}

func (a *App) Server() *echo.Echo {
	if a.server == nil {

		if a.logger != nil {
			a.logger.Warn("Server not properly initialized through dependency injection")
		}
		return nil
	}
	return a.server.Echo()
}

func (a *App) BrxServer() *server.Server {
	return a.server
}

func (a *App) Database() *gorm.DB {
	return a.db
}

func (a *App) DB() *gorm.DB {
	return a.db
}

func (a *App) Logger() *logging.Service {
	return a.logger
}

func (a *App) Config() *config.Config {
	return a.config
}

func (a *App) InertiaService() *inertia.Service {
	return a.inertiaSvc
}

func (a *App) RegisterRoutes(fn func(*echo.Echo)) {
	if server := a.Server(); server != nil {
		fn(server)
	}
}

func (a *App) Get(path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) {
	if server := a.Server(); server != nil {
		server.GET(path, handler, middleware...)
	}
}

func (a *App) Post(path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) {
	if server := a.Server(); server != nil {
		server.POST(path, handler, middleware...)
	}
}

func (a *App) Put(path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) {
	if server := a.Server(); server != nil {
		server.PUT(path, handler, middleware...)
	}
}

func (a *App) Delete(path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) {
	if server := a.Server(); server != nil {
		server.DELETE(path, handler, middleware...)
	}
}

func (a *App) Patch(path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) {
	if server := a.Server(); server != nil {
		server.PATCH(path, handler, middleware...)
	}
}
