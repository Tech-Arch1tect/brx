package options

import "github.com/tech-arch1tect/brx/config"

type Options struct {
	Config *config.Config
}

type Option func(*Options)

func WithConfig(cfg *config.Config) Option {
	return func(opts *Options) {
		opts.Config = cfg
	}
}
