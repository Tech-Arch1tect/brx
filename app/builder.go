package app

import (
	"context"
	"fmt"

	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/database"
	"github.com/tech-arch1tect/brx/middleware/inertiashared"
	"github.com/tech-arch1tect/brx/middleware/ratelimit"
	"github.com/tech-arch1tect/brx/server"
	"github.com/tech-arch1tect/brx/services/auth"
	"github.com/tech-arch1tect/brx/services/inertia"
	"github.com/tech-arch1tect/brx/services/logging"
	"github.com/tech-arch1tect/brx/services/mail"
	"github.com/tech-arch1tect/brx/services/refreshtoken"
	"github.com/tech-arch1tect/brx/services/revocation"
	"github.com/tech-arch1tect/brx/services/templates"
	"github.com/tech-arch1tect/brx/services/totp"
	"github.com/tech-arch1tect/brx/session"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

type AppBuilder struct {
	config      *config.Config
	services    map[string]bool
	models      []any
	fxOptions   []fx.Option
	middlewares []string
	errors      []error
	sslCertFile string
	sslKeyFile  string
}

func NewApp() *AppBuilder {
	return &AppBuilder{
		services:    make(map[string]bool),
		models:      make([]any, 0),
		fxOptions:   make([]fx.Option, 0),
		middlewares: make([]string, 0),
		errors:      make([]error, 0),
	}
}

func (b *AppBuilder) WithConfig(cfg *config.Config) *AppBuilder {
	if cfg == nil {
		b.addError("config cannot be nil")
		return b
	}
	b.config = cfg
	return b
}

func (b *AppBuilder) WithAutoConfig() *AppBuilder {
	cfg := &config.Config{}
	if err := config.LoadConfig(cfg); err != nil {
		b.addError(fmt.Sprintf("failed to load config: %v", err))
		return b
	}
	b.config = cfg
	return b
}

func (b *AppBuilder) WithDatabase(models ...any) *AppBuilder {
	b.services["database"] = true
	b.models = append(b.models, models...)
	return b
}

func (b *AppBuilder) WithTemplates() *AppBuilder {
	b.services["templates"] = true
	return b
}

func (b *AppBuilder) WithInertia() *AppBuilder {
	b.services["inertia"] = true
	b.middlewares = append(b.middlewares, "inertia")
	return b
}

func (b *AppBuilder) WithInertiaNoMiddleware() *AppBuilder {
	b.services["inertia"] = true
	return b
}

func (b *AppBuilder) WithSessions(opts ...*session.Options) *AppBuilder {
	b.services["sessions"] = true
	b.middlewares = append(b.middlewares, "sessions")

	if len(opts) > 0 {
		b.fxOptions = append(b.fxOptions, fx.Supply(opts[0]))
	} else {

		var nilOpts *session.Options
		b.fxOptions = append(b.fxOptions, fx.Supply(nilOpts))
	}
	return b
}

func (b *AppBuilder) WithSessionsNoMiddleware(opts ...*session.Options) *AppBuilder {
	b.services["sessions"] = true

	if len(opts) > 0 {
		b.fxOptions = append(b.fxOptions, fx.Supply(opts[0]))
	} else {

		var nilOpts *session.Options
		b.fxOptions = append(b.fxOptions, fx.Supply(nilOpts))
	}
	return b
}

func (b *AppBuilder) WithAuth() *AppBuilder {
	b.services["auth"] = true
	return b
}

func (b *AppBuilder) WithMail() *AppBuilder {
	b.services["mail"] = true
	return b
}

func (b *AppBuilder) WithTOTP() *AppBuilder {
	b.services["totp"] = true
	return b
}

func (b *AppBuilder) WithJWT() *AppBuilder {
	b.services["jwt"] = true
	b.services["database"] = true
	b.models = append(b.models, &refreshtoken.RefreshToken{})
	return b
}

func (b *AppBuilder) WithJWTRevocation() *AppBuilder {
	b.services["jwt_revocation"] = true
	b.services["jwt"] = true
	return b
}

func (b *AppBuilder) WithSSL(certFile, keyFile string) *AppBuilder {
	if certFile == "" || keyFile == "" {
		b.addError("SSL cert file and key file cannot be empty")
		return b
	}
	b.services["ssl"] = true
	b.sslCertFile = certFile
	b.sslKeyFile = keyFile
	return b
}

func (b *AppBuilder) WithFxOptions(opts ...fx.Option) *AppBuilder {
	b.fxOptions = append(b.fxOptions, opts...)
	return b
}

func (b *AppBuilder) Build() (*App, error) {

	if err := b.validate(); err != nil {
		return nil, err
	}

	if b.config == nil {
		if err := b.WithAutoConfig().validate(); err != nil {
			return nil, err
		}
	}

	logger, err := b.createLogger()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	services, err := b.buildServices(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to build services: %w", err)
	}

	fxOptions := b.buildFxOptions(services, logger)

	app := &App{
		config:     b.config,
		logger:     logger,
		services:   services,
		inertiaSvc: services.inertia,
		db:         services.database,
		server:     nil,
	}

	fxOptions = append(fxOptions, fx.Invoke(func(srv *server.Server) {
		app.server = srv
	}))

	fxApp := fx.New(fxOptions...)
	app.fx = fxApp

	return app, nil
}

func (b *AppBuilder) addError(msg string) {
	b.errors = append(b.errors, fmt.Errorf("%s", msg))
}

func (b *AppBuilder) validate() error {

	if len(b.errors) > 0 {
		return fmt.Errorf("configuration errors: %v", b.errors)
	}

	if b.services["jwt"] && !b.services["database"] {
		return fmt.Errorf("JWT requires database support")
	}

	if b.services["jwt_revocation"] && !b.services["jwt"] {
		return fmt.Errorf("JWT revocation requires JWT support")
	}

	if b.services["auth"] && !b.services["database"] {
		b.services["database"] = true
	}

	if b.services["sessions"] && !b.services["database"] {
		b.services["database"] = true
	}

	if b.services["totp"] && !b.services["database"] {
		b.services["database"] = true
	}

	return nil
}

func (b *AppBuilder) createLogger() (*logging.Service, error) {
	if b.config == nil {
		return nil, fmt.Errorf("config required for logger creation")
	}

	return logging.NewService(logging.Config{
		Level:      logging.LogLevel(b.config.Log.Level),
		Format:     b.config.Log.Format,
		OutputPath: b.config.Log.Output,
	})
}

type ServiceContainer struct {
	database  *gorm.DB
	templates *templates.Service
	inertia   *inertia.Service
}

type SSLConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

func (b *AppBuilder) buildServices(logger *logging.Service) (*ServiceContainer, error) {
	services := &ServiceContainer{}

	if b.services["database"] {
		modelsOpt := &database.ModelsOption{}
		if len(b.models) > 0 {
			modelsOpt = database.WithModels(b.models...)
		}

		db, err := database.ProvideDatabase(*b.config, modelsOpt, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize database: %w", err)
		}
		services.database = db
	}

	if b.services["templates"] {
		services.templates = templates.New(&b.config.Templates, logger)
	}

	if b.services["inertia"] {
		services.inertia = inertia.New(&b.config.Inertia, logger)
	}

	return services, nil
}

func (b *AppBuilder) buildFxOptions(services *ServiceContainer, logger *logging.Service) []fx.Option {
	var options []fx.Option

	sslConfig := &SSLConfig{
		Enabled:  b.services["ssl"],
		CertFile: b.sslCertFile,
		KeyFile:  b.sslKeyFile,
	}

	options = append(options,
		fx.Supply(b.config),
		fx.Supply(logger),
		fx.Supply(sslConfig),
		fx.NopLogger,
	)

	if services.database != nil {
		options = append(options, fx.Supply(services.database))
	}
	if services.templates != nil {
		options = append(options, fx.Supply(services.templates))
	}
	if services.inertia != nil {
		options = append(options, fx.Supply(services.inertia))
	}

	options = append(options, server.NewProvider())

	options = append(options, fx.Provide(ratelimit.ProvideRateLimitStore))

	if b.services["mail"] {
		options = append(options, mail.Module)
	}
	if b.services["sessions"] {
		options = append(options, session.Module)
	}
	if b.services["auth"] {
		options = append(options, auth.Module)
	}
	if b.services["totp"] {
		options = append(options, totp.Module)
	}
	if b.services["jwt"] {
		options = append(options, fx.Provide(refreshtoken.ProvideRefreshTokenService))
	}
	if b.services["jwt_revocation"] {
		options = append(options, revocation.Module)
	}

	options = append(options, b.fxOptions...)

	options = append(options, b.buildMiddlewareHooks(services)...)

	options = append(options, b.buildLifecycleHooks(services)...)

	return options
}

func (b *AppBuilder) buildMiddlewareHooks(services *ServiceContainer) []fx.Option {
	var hooks []fx.Option

	for _, middleware := range b.middlewares {
		switch middleware {
		case "sessions":
			hooks = append(hooks, fx.Invoke(func(srv *server.Server, sessionMgr *session.Manager) {
				if sessionMgr != nil && srv != nil {
					srv.Echo().Use(session.Middleware(sessionMgr))
				}
			}))
		case "inertia":
			if services.inertia != nil {
				hooks = append(hooks, fx.Invoke(func(srv *server.Server, inertiaSvc *inertia.Service, userProvider inertiashared.UserProvider) {
					if srv != nil {
						srv.Echo().Use(inertiaSvc.Middleware())

						middlewareConfig := inertiashared.Config{
							AuthEnabled:  true,
							FlashEnabled: true,
							UserProvider: userProvider,
						}
						srv.Echo().Use(inertiashared.MiddlewareWithConfig(middlewareConfig))
					}
				}))
			}
		}
	}

	return hooks
}

func (b *AppBuilder) buildLifecycleHooks(services *ServiceContainer) []fx.Option {
	var hooks []fx.Option

	if services.templates != nil {
		hooks = append(hooks, fx.Invoke(func(lc fx.Lifecycle, svc *templates.Service) {
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					return svc.LoadTemplates()
				},
			})
		}))
	}

	if services.inertia != nil {
		hooks = append(hooks, fx.Invoke(func(lc fx.Lifecycle, svc *inertia.Service) {
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					rootViewPath := b.config.Inertia.RootView
					if rootViewPath == "" {
						rootViewPath = "app.html"
					}

					if err := svc.InitializeFromFile(rootViewPath); err != nil {
						return err
					}

					if !b.config.Inertia.Development {
						if err := svc.LoadManifest("public/build/.vite/manifest.json"); err != nil {

							return nil
						}
					}

					svc.ShareAssetData()
					return nil
				},
			})
		}))
	}

	return hooks
}
