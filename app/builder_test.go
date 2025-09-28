package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tech-arch1tect/brx/session"
	"go.uber.org/fx"
)

func TestNewApp(t *testing.T) {
	builder := NewApp()

	assert.NotNil(t, builder)
	assert.NotNil(t, builder.services)
	assert.NotNil(t, builder.models)
	assert.NotNil(t, builder.fxOptions)
	assert.NotNil(t, builder.middlewares)
	assert.NotNil(t, builder.errors)
	assert.Empty(t, builder.services)
	assert.Empty(t, builder.models)
	assert.Empty(t, builder.fxOptions)
	assert.Empty(t, builder.middlewares)
	assert.Empty(t, builder.errors)
}

func TestAppBuilder_WithConfig(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := createTestConfig()
		builder := NewApp()

		result := builder.WithConfig(cfg)

		assert.Equal(t, builder, result)
		assert.Equal(t, cfg, builder.config)
	})

	t.Run("nil config", func(t *testing.T) {
		builder := NewApp()

		result := builder.WithConfig(nil)

		assert.Equal(t, builder, result)
		assert.Nil(t, builder.config)
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "config cannot be nil")
	})
}

func TestAppBuilder_WithAutoConfig(t *testing.T) {
	t.Run("successful auto config", func(t *testing.T) {
		builder := NewApp()

		result := builder.WithAutoConfig()

		assert.Equal(t, builder, result)
		if len(builder.errors) == 0 {
			assert.NotNil(t, builder.config)
		}
	})
}

func TestAppBuilder_WithDatabase(t *testing.T) {
	builder := NewApp()

	type TestModel struct {
		ID   uint   `gorm:"primaryKey"`
		Name string `gorm:"size:255"`
	}

	model1 := TestModel{}
	model2 := &TestModel{}

	result := builder.WithDatabase(model1, model2)

	assert.Equal(t, builder, result)
	assert.True(t, builder.services["database"])
	assert.Len(t, builder.models, 2)
	assert.Contains(t, builder.models, model1)
	assert.Contains(t, builder.models, model2)
}

func TestAppBuilder_WithTemplates(t *testing.T) {
	builder := NewApp()

	result := builder.WithTemplates()

	assert.Equal(t, builder, result)
	assert.True(t, builder.services["templates"])
}

func TestAppBuilder_WithInertia(t *testing.T) {
	builder := NewApp()

	result := builder.WithInertia()

	assert.Equal(t, builder, result)
	assert.True(t, builder.services["inertia"])
	assert.Contains(t, builder.middlewares, "inertia")
}

func TestAppBuilder_WithInertiaNoMiddleware(t *testing.T) {
	builder := NewApp()

	result := builder.WithInertiaNoMiddleware()

	assert.Equal(t, builder, result)
	assert.True(t, builder.services["inertia"])
	assert.NotContains(t, builder.middlewares, "inertia")
}

func TestAppBuilder_WithSessions(t *testing.T) {
	t.Run("with options", func(t *testing.T) {
		builder := NewApp()
		opts := &session.Options{}

		result := builder.WithSessions(opts)

		assert.Equal(t, builder, result)
		assert.True(t, builder.services["sessions"])
		assert.Contains(t, builder.middlewares, "sessions")
		assert.Len(t, builder.fxOptions, 1)
	})

	t.Run("without options", func(t *testing.T) {
		builder := NewApp()

		result := builder.WithSessions()

		assert.Equal(t, builder, result)
		assert.True(t, builder.services["sessions"])
		assert.Contains(t, builder.middlewares, "sessions")
		assert.Len(t, builder.fxOptions, 1)
	})
}

func TestAppBuilder_WithSessionsNoMiddleware(t *testing.T) {
	t.Run("with options", func(t *testing.T) {
		builder := NewApp()
		opts := &session.Options{}

		result := builder.WithSessionsNoMiddleware(opts)

		assert.Equal(t, builder, result)
		assert.True(t, builder.services["sessions"])
		assert.NotContains(t, builder.middlewares, "sessions")
		assert.Len(t, builder.fxOptions, 1)
	})

	t.Run("without options", func(t *testing.T) {
		builder := NewApp()

		result := builder.WithSessionsNoMiddleware()

		assert.Equal(t, builder, result)
		assert.True(t, builder.services["sessions"])
		assert.NotContains(t, builder.middlewares, "sessions")
		assert.Len(t, builder.fxOptions, 1)
	})
}

func TestAppBuilder_WithAuth(t *testing.T) {
	builder := NewApp()

	result := builder.WithAuth()

	assert.Equal(t, builder, result)
	assert.True(t, builder.services["auth"])
}

func TestAppBuilder_WithMail(t *testing.T) {
	builder := NewApp()

	result := builder.WithMail()

	assert.Equal(t, builder, result)
	assert.True(t, builder.services["mail"])
}

func TestAppBuilder_WithTOTP(t *testing.T) {
	builder := NewApp()

	result := builder.WithTOTP()

	assert.Equal(t, builder, result)
	assert.True(t, builder.services["totp"])
}

func TestAppBuilder_WithJWT(t *testing.T) {
	builder := NewApp()

	result := builder.WithJWT()

	assert.Equal(t, builder, result)
	assert.True(t, builder.services["jwt"])
	assert.True(t, builder.services["database"])
	assert.Len(t, builder.models, 1)
}

func TestAppBuilder_WithJWTRevocation(t *testing.T) {
	builder := NewApp()

	result := builder.WithJWTRevocation()

	assert.Equal(t, builder, result)
	assert.True(t, builder.services["jwt_revocation"])
	assert.True(t, builder.services["jwt"])
}

func TestAppBuilder_WithSSL(t *testing.T) {
	t.Run("valid SSL files", func(t *testing.T) {
		builder := NewApp()

		result := builder.WithSSL("cert.pem", "key.pem")

		assert.Equal(t, builder, result)
		assert.True(t, builder.services["ssl"])
		assert.Equal(t, "cert.pem", builder.sslCertFile)
		assert.Equal(t, "key.pem", builder.sslKeyFile)
	})

	t.Run("empty cert file", func(t *testing.T) {
		builder := NewApp()

		result := builder.WithSSL("", "key.pem")

		assert.Equal(t, builder, result)
		assert.False(t, builder.services["ssl"])
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "SSL cert file and key file cannot be empty")
	})

	t.Run("empty key file", func(t *testing.T) {
		builder := NewApp()

		result := builder.WithSSL("cert.pem", "")

		assert.Equal(t, builder, result)
		assert.False(t, builder.services["ssl"])
		assert.Len(t, builder.errors, 1)
		assert.Contains(t, builder.errors[0].Error(), "SSL cert file and key file cannot be empty")
	})
}

func TestAppBuilder_WithFxOptions(t *testing.T) {
	builder := NewApp()
	option1 := fx.NopLogger
	option2 := fx.StartTimeout(0)

	result := builder.WithFxOptions(option1, option2)

	assert.Equal(t, builder, result)
	assert.Len(t, builder.fxOptions, 2)
}

func TestAppBuilder_validate(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		builder := NewApp()

		err := builder.validate()

		assert.NoError(t, err)
	})

	t.Run("existing errors", func(t *testing.T) {
		builder := NewApp()
		builder.addError("test error")

		err := builder.validate()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "configuration errors")
		assert.Contains(t, err.Error(), "test error")
	})

	t.Run("JWT without database", func(t *testing.T) {
		builder := NewApp()
		builder.services["jwt"] = true

		err := builder.validate()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "JWT requires database support")
	})

	t.Run("JWT revocation without JWT", func(t *testing.T) {
		builder := NewApp()
		builder.services["jwt_revocation"] = true

		err := builder.validate()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "JWT revocation requires JWT support")
	})

	t.Run("auth implies database", func(t *testing.T) {
		builder := NewApp()
		builder.services["auth"] = true

		err := builder.validate()

		assert.NoError(t, err)
		assert.True(t, builder.services["database"])
	})

	t.Run("sessions implies database", func(t *testing.T) {
		builder := NewApp()
		builder.services["sessions"] = true

		err := builder.validate()

		assert.NoError(t, err)
		assert.True(t, builder.services["database"])
	})

	t.Run("totp implies database", func(t *testing.T) {
		builder := NewApp()
		builder.services["totp"] = true

		err := builder.validate()

		assert.NoError(t, err)
		assert.True(t, builder.services["database"])
	})
}

func TestAppBuilder_createLogger(t *testing.T) {
	t.Run("successful logger creation", func(t *testing.T) {
		cfg := createTestConfig()
		builder := NewApp().WithConfig(cfg)

		logger, err := builder.createLogger()

		assert.NoError(t, err)
		assert.NotNil(t, logger)
	})

	t.Run("nil config", func(t *testing.T) {
		builder := NewApp()

		logger, err := builder.createLogger()

		assert.Error(t, err)
		assert.Nil(t, logger)
		assert.Contains(t, err.Error(), "config required for logger creation")
	})
}

func TestAppBuilder_buildServices(t *testing.T) {
	t.Run("no services", func(t *testing.T) {
		cfg := createTestConfig()
		builder := NewApp().WithConfig(cfg)
		logger, _ := builder.createLogger()

		services, err := builder.buildServices(logger)

		assert.NoError(t, err)
		assert.NotNil(t, services)
		assert.Nil(t, services.database)
		assert.Nil(t, services.templates)
		assert.Nil(t, services.inertia)
	})

	t.Run("with database service", func(t *testing.T) {
		cfg := createTestConfig()
		builder := NewApp().WithConfig(cfg).WithDatabase()
		logger, _ := builder.createLogger()

		services, err := builder.buildServices(logger)

		assert.NoError(t, err)
		assert.NotNil(t, services)
		assert.NotNil(t, services.database)
	})

	t.Run("with templates service", func(t *testing.T) {
		cfg := createTestConfig()
		builder := NewApp().WithConfig(cfg).WithTemplates()
		logger, _ := builder.createLogger()

		services, err := builder.buildServices(logger)

		assert.NoError(t, err)
		assert.NotNil(t, services)
		assert.NotNil(t, services.templates)
	})

	t.Run("with inertia service", func(t *testing.T) {
		cfg := createTestConfig()
		builder := NewApp().WithConfig(cfg).WithInertia()
		logger, _ := builder.createLogger()

		services, err := builder.buildServices(logger)

		assert.NoError(t, err)
		assert.NotNil(t, services)
		assert.NotNil(t, services.inertia)
	})

	t.Run("with models", func(t *testing.T) {
		cfg := createTestConfig()
		type TestModel struct {
			ID uint `gorm:"primaryKey"`
		}
		builder := NewApp().WithConfig(cfg).WithDatabase(TestModel{})
		logger, _ := builder.createLogger()

		services, err := builder.buildServices(logger)

		assert.NoError(t, err)
		assert.NotNil(t, services)
		assert.NotNil(t, services.database)
	})
}

func TestAppBuilder_Build(t *testing.T) {
	t.Run("successful build with minimal config", func(t *testing.T) {
		cfg := createTestConfig()
		builder := NewApp().WithConfig(cfg)

		app, err := builder.Build()

		assert.NoError(t, err)
		assert.NotNil(t, app)
		assert.Equal(t, cfg, app.config)
		assert.NotNil(t, app.logger)
		assert.NotNil(t, app.services)
		assert.NotNil(t, app.fx)
	})

	t.Run("build with auto config", func(t *testing.T) {
		builder := NewApp().WithAutoConfig()

		app, err := builder.Build()

		if len(builder.errors) == 0 {
			assert.NoError(t, err)
			assert.NotNil(t, app)
		} else {
			assert.Error(t, err)
		}
	})

	t.Run("build with validation error", func(t *testing.T) {
		builder := NewApp().WithConfig(nil)

		app, err := builder.Build()

		assert.Error(t, err)
		assert.Nil(t, app)
	})

	t.Run("build with database service", func(t *testing.T) {
		cfg := createTestConfig()
		builder := NewApp().WithConfig(cfg).WithDatabase()

		app, err := builder.Build()

		assert.NoError(t, err)
		assert.NotNil(t, app)
		assert.NotNil(t, app.db)
	})

	t.Run("build with inertia service", func(t *testing.T) {
		cfg := createTestConfig()
		builder := NewApp().WithConfig(cfg).WithInertia()

		app, err := builder.Build()

		assert.NoError(t, err)
		assert.NotNil(t, app)
		assert.NotNil(t, app.inertiaSvc)
	})

	t.Run("build with all services", func(t *testing.T) {
		cfg := createTestConfig()
		builder := NewApp().
			WithConfig(cfg).
			WithDatabase().
			WithTemplates().
			WithInertia().
			WithSessions().
			WithAuth().
			WithMail().
			WithTOTP().
			WithJWT().
			WithJWTRevocation()

		app, err := builder.Build()

		assert.NoError(t, err)
		assert.NotNil(t, app)
		assert.NotNil(t, app.config)
		assert.NotNil(t, app.logger)
		assert.NotNil(t, app.services)
		assert.NotNil(t, app.fx)
	})
}

func TestAppBuilder_addError(t *testing.T) {
	builder := NewApp()

	builder.addError("test error")

	assert.Len(t, builder.errors, 1)
	assert.Equal(t, "test error", builder.errors[0].Error())
}

func TestSSLConfig(t *testing.T) {
	sslConfig := &SSLConfig{
		Enabled:  true,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	}

	assert.True(t, sslConfig.Enabled)
	assert.Equal(t, "cert.pem", sslConfig.CertFile)
	assert.Equal(t, "key.pem", sslConfig.KeyFile)
}

func TestServiceContainer(t *testing.T) {
	container := &ServiceContainer{}

	assert.Nil(t, container.database)
	assert.Nil(t, container.templates)
	assert.Nil(t, container.inertia)
}
