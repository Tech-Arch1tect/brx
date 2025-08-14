package ratelimit

import (
	"github.com/tech-arch1tect/brx/config"
)

func ProvideRateLimitStore(cfg *config.Config) Store {
	return NewStore(&cfg.RateLimit)
}
