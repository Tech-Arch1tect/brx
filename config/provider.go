package config

import "go.uber.org/fx"

func NewProvider(customConfig *Config) fx.Option {
	if customConfig != nil {
		return fx.Provide(func() *Config {
			return customConfig
		})
	}

	return fx.Provide(func() *Config {
		cfg := &Config{}
		if err := LoadConfig(cfg); err != nil {
			panic(err)
		}
		return cfg
	})
}
