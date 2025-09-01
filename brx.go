package brx

import (
	"github.com/tech-arch1tect/brx/app"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/internal/options"
	"github.com/tech-arch1tect/brx/session"
)

type App = app.App

func New(opts ...options.Option) *App {
	return app.New(opts...)
}

func WithConfig(cfg *config.Config) options.Option {
	return options.WithConfig(cfg)
}

func WithTemplates() options.Option {
	return options.WithTemplates()
}

func WithInertia() options.Option {
	return options.WithInertia()
}

func WithInertiaNoGlobalMiddleware() options.Option {
	return options.WithInertiaNoGlobalMiddleware()
}

func WithDatabase(models ...any) options.Option {
	return options.WithDatabase(models...)
}

func WithSessions(sessionOpts ...*session.Options) options.Option {
	return options.WithSessions(sessionOpts...)
}

func WithSessionsNoGlobalMiddleware(sessionOpts ...*session.Options) options.Option {
	return options.WithSessionsNoGlobalMiddleware(sessionOpts...)
}

func WithAuth() options.Option {
	return options.WithAuth()
}

func WithMail() options.Option {
	return options.WithMail()
}

func WithTOTP() options.Option {
	return options.WithTOTP()
}

func WithJWT() options.Option {
	return options.WithJWT()
}

func WithJWTRevocation() options.Option {
	return options.WithJWTRevocation()
}

func WithFxOptions(fxOpts ...any) options.Option {
	return options.WithFxOptions(fxOpts...)
}

func WithSSL(certFile, keyFile string) options.Option {
	return options.WithSSL(certFile, keyFile)
}
