package app

import (
	"context"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/server"
	"github.com/tech-arch1tect/brx/services/inertia"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/fx"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func createTestConfig() *config.Config {
	return &config.Config{
		App: config.AppConfig{
			Name: "test-app",
			URL:  "http://localhost:8080",
		},
		Server: config.ServerConfig{
			Host: "localhost",
			Port: "8080",
		},
		Log: config.LogConfig{
			Level:  "debug",
			Format: "console",
			Output: "stdout",
		},
		Database: config.DatabaseConfig{
			Driver: "sqlite",
			DSN:    ":memory:",
		},
		Inertia: config.InertiaConfig{
			Enabled:     true,
			Version:     "test",
			Development: true,
		},
		Templates: config.TemplatesConfig{
			Enabled:   true,
			Dir:       "templates",
			Extension: ".html",
		},
	}
}

func createTestApp() *App {
	cfg := createTestConfig()
	logger, _ := logging.NewService(logging.Config{
		Level:      logging.Debug,
		Format:     "console",
		OutputPath: "stdout",
	})

	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})

	inertiaSvc := inertia.New(&cfg.Inertia, logger)

	srv := &server.Server{}

	services := &ServiceContainer{
		database: db,
		inertia:  inertiaSvc,
	}

	return &App{
		fx:         nil,
		config:     cfg,
		logger:     logger,
		services:   services,
		inertiaSvc: inertiaSvc,
		db:         db,
		server:     srv,
	}
}

func TestApp_Start(t *testing.T) {
	t.Run("successful start", func(t *testing.T) {
		fxApp := fx.New(fx.NopLogger)
		app := &App{fx: fxApp}

		err := app.Start()

		assert.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		fxApp.Stop(ctx)
	})

	t.Run("start with error", func(t *testing.T) {
		fxApp := fx.New(
			fx.NopLogger,
			fx.Invoke(func() error {
				return assert.AnError
			}),
		)
		app := &App{fx: fxApp}

		err := app.Start()

		assert.Error(t, err)
	})
}

func TestApp_StartTest(t *testing.T) {
	t.Run("successful test start", func(t *testing.T) {
		fxApp := fx.New(fx.NopLogger)
		app := &App{fx: fxApp}

		err := app.StartTest()

		assert.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		fxApp.Stop(ctx)
	})
}

func TestApp_Stop(t *testing.T) {
	t.Run("successful stop", func(t *testing.T) {
		fxApp := fx.New(fx.NopLogger)
		app := &App{fx: fxApp}

		ctx := context.Background()
		fxApp.Start(ctx)

		app.Stop()
	})

	t.Run("stop with timeout", func(t *testing.T) {
		fxApp := fx.New(
			fx.NopLogger,
			fx.Invoke(func(lc fx.Lifecycle) {
				lc.Append(fx.Hook{
					OnStop: func(ctx context.Context) error {
						select {
						case <-ctx.Done():
							return ctx.Err()
						case <-time.After(5 * time.Second):
							return nil
						}
					},
				})
			}),
		)
		app := &App{fx: fxApp}

		ctx := context.Background()
		fxApp.Start(ctx)

		app.Stop()
	})

	t.Run("stop without logger", func(t *testing.T) {
		fxApp := fx.New(
			fx.NopLogger,
			fx.Invoke(func() error {
				return assert.AnError
			}),
		)
		app := &App{fx: fxApp, logger: nil}

		app.Stop()
	})
}

func TestApp_StopTest(t *testing.T) {
	t.Run("successful test stop", func(t *testing.T) {
		fxApp := fx.New(fx.NopLogger)
		app := &App{fx: fxApp}

		ctx := context.Background()
		fxApp.Start(ctx)

		app.StopTest()
	})

	t.Run("test stop with error", func(t *testing.T) {
		fxApp := fx.New(
			fx.NopLogger,
			fx.Invoke(func(lc fx.Lifecycle) {
				lc.Append(fx.Hook{
					OnStop: func(ctx context.Context) error {
						return assert.AnError
					},
				})
			}),
		)
		app := &App{fx: fxApp, logger: nil}

		ctx := context.Background()
		fxApp.Start(ctx)

		app.StopTest()
	})
}

func TestApp_Server(t *testing.T) {
	t.Run("server exists", func(t *testing.T) {
		cfg := createTestConfig()
		logger, _ := logging.NewService(logging.Config{
			Level:      logging.Debug,
			Format:     "console",
			OutputPath: "stdout",
		})
		srv := server.New(cfg, logger)
		app := &App{server: srv}

		result := app.Server()

		assert.Equal(t, srv.Echo(), result)
		assert.NotNil(t, result)
	})

	t.Run("server is nil", func(t *testing.T) {
		app := createTestApp()
		app.server = nil

		result := app.Server()

		assert.Nil(t, result)
	})

	t.Run("server without logger", func(t *testing.T) {
		app := &App{server: nil, logger: nil}

		result := app.Server()

		assert.Nil(t, result)
	})
}

func TestApp_BrxServer(t *testing.T) {
	srv := &server.Server{}
	app := &App{server: srv}

	result := app.BrxServer()

	assert.Equal(t, srv, result)
}

func TestApp_Database(t *testing.T) {
	app := createTestApp()

	result := app.Database()

	assert.Equal(t, app.db, result)
}

func TestApp_DB(t *testing.T) {
	app := createTestApp()

	result := app.DB()

	assert.Equal(t, app.db, result)
}

func TestApp_Logger(t *testing.T) {
	app := createTestApp()

	result := app.Logger()

	assert.Equal(t, app.logger, result)
}

func TestApp_Config(t *testing.T) {
	app := createTestApp()

	result := app.Config()

	assert.Equal(t, app.config, result)
}

func TestApp_InertiaService(t *testing.T) {
	app := createTestApp()

	result := app.InertiaService()

	assert.Equal(t, app.inertiaSvc, result)
}

func TestApp_RegisterRoutes(t *testing.T) {
	t.Run("with valid server", func(t *testing.T) {
		cfg := createTestConfig()
		logger, _ := logging.NewService(logging.Config{
			Level:      logging.Debug,
			Format:     "console",
			OutputPath: "stdout",
		})
		srv := server.New(cfg, logger)
		app := &App{server: srv}

		called := false
		app.RegisterRoutes(func(server *echo.Echo) {
			called = true
			assert.Equal(t, srv.Echo(), server)
		})

		assert.True(t, called)
	})

	t.Run("with nil server", func(t *testing.T) {
		app := &App{server: nil}

		called := false
		app.RegisterRoutes(func(server *echo.Echo) {
			called = true
		})

		assert.False(t, called)
	})
}

func TestApp_HTTPMethods(t *testing.T) {
	cfg := createTestConfig()
	logger, _ := logging.NewService(logging.Config{
		Level:      logging.Debug,
		Format:     "console",
		OutputPath: "stdout",
	})
	srv := server.New(cfg, logger)
	app := &App{server: srv}
	e := srv.Echo()

	handler := func(c echo.Context) error {
		return c.String(200, "OK")
	}

	t.Run("GET", func(t *testing.T) {
		app.Get("/test", handler)

		routes := e.Routes()
		found := false
		for _, route := range routes {
			if route.Path == "/test" && route.Method == "GET" {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("POST", func(t *testing.T) {
		app.Post("/test-post", handler)

		routes := e.Routes()
		found := false
		for _, route := range routes {
			if route.Path == "/test-post" && route.Method == "POST" {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("PUT", func(t *testing.T) {
		app.Put("/test-put", handler)

		routes := e.Routes()
		found := false
		for _, route := range routes {
			if route.Path == "/test-put" && route.Method == "PUT" {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("DELETE", func(t *testing.T) {
		app.Delete("/test-delete", handler)

		routes := e.Routes()
		found := false
		for _, route := range routes {
			if route.Path == "/test-delete" && route.Method == "DELETE" {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("PATCH", func(t *testing.T) {
		app.Patch("/test-patch", handler)

		routes := e.Routes()
		found := false
		for _, route := range routes {
			if route.Path == "/test-patch" && route.Method == "PATCH" {
				found = true
				break
			}
		}
		assert.True(t, found)
	})
}

func TestApp_HTTPMethodsWithNilServer(t *testing.T) {
	app := &App{server: nil}

	handler := func(c echo.Context) error {
		return c.String(200, "OK")
	}

	t.Run("GET with nil server", func(t *testing.T) {
		app.Get("/test", handler)
	})

	t.Run("POST with nil server", func(t *testing.T) {
		app.Post("/test", handler)
	})

	t.Run("PUT with nil server", func(t *testing.T) {
		app.Put("/test", handler)
	})

	t.Run("DELETE with nil server", func(t *testing.T) {
		app.Delete("/test", handler)
	})

	t.Run("PATCH with nil server", func(t *testing.T) {
		app.Patch("/test", handler)
	})
}
