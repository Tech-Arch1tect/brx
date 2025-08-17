package options

import (
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/session"
)

type Options struct {
	Config          *config.Config
	EnableTemplates bool
	EnableInertia   bool
	EnableDatabase  bool
	DatabaseModels  []any
	EnableSessions  bool
	SessionOptions  *session.Options
	EnableAuth      bool
	EnableMail      bool
	EnableTOTP      bool
	ExtraFxOptions  []any
}

type Option func(*Options)

func WithConfig(cfg *config.Config) Option {
	return func(opts *Options) {
		opts.Config = cfg
	}
}

func WithTemplates() Option {
	return func(opts *Options) {
		opts.EnableTemplates = true
	}
}

func WithInertia() Option {
	return func(opts *Options) {
		opts.EnableInertia = true
	}
}

func WithDatabase(models ...any) Option {
	return func(opts *Options) {
		opts.EnableDatabase = true
		opts.DatabaseModels = models
	}
}

func WithSessions(sessionOpts ...*session.Options) Option {
	return func(opts *Options) {
		opts.EnableSessions = true
		if len(sessionOpts) > 0 {
			opts.SessionOptions = sessionOpts[0]
		}
	}
}

func WithAuth() Option {
	return func(opts *Options) {
		opts.EnableAuth = true
	}
}

func WithMail() Option {
	return func(opts *Options) {
		opts.EnableMail = true
	}
}

func WithTOTP() Option {
	return func(opts *Options) {
		opts.EnableTOTP = true
	}
}

func WithFxOptions(fxOpts ...any) Option {
	return func(opts *Options) {
		opts.ExtraFxOptions = append(opts.ExtraFxOptions, fxOpts...)
	}
}
