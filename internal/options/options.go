package options

import "github.com/tech-arch1tect/brx/config"

type Options struct {
	Config          *config.Config
	EnableTemplates bool
	EnableInertia   bool
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
