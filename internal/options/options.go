package options

import "github.com/tech-arch1tect/brx/config"

type Options struct {
	Config          *config.Config
	EnableTemplates bool
	EnableInertia   bool
	EnableDatabase  bool
	DatabaseModels  []any
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

func WithFxOptions(fxOpts ...any) Option {
	return func(opts *Options) {
		opts.ExtraFxOptions = append(opts.ExtraFxOptions, fxOpts...)
	}
}
