package ratelimit

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/config"
)

type Config struct {
	Store          Store
	Rate           int
	Period         time.Duration
	CountMode      config.CountingMode
	KeyGenerator   func(c echo.Context) string
	OnLimitReached func(c echo.Context) error
}

func Middleware(cfg *Config) echo.MiddlewareFunc {
	if cfg.Store == nil {
		cfg.Store = NewMemoryStore()
	}

	if cfg.Rate <= 0 {
		cfg.Rate = 10
	}

	if cfg.Period <= 0 {
		cfg.Period = time.Minute
	}

	if cfg.KeyGenerator == nil {
		cfg.KeyGenerator = DefaultKeyGenerator
	}

	if cfg.OnLimitReached == nil {
		cfg.OnLimitReached = DefaultOnLimitReached
	}

	if cfg.CountMode == "" {
		cfg.CountMode = config.CountAll
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key := cfg.KeyGenerator(c)
			now := time.Now()
			resetTime := now.Add(cfg.Period)

			count, existingResetTime, exists := cfg.Store.Get(key)
			if exists {
				resetTime = existingResetTime
			}

			if count >= cfg.Rate {
				c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(cfg.Rate))
				c.Response().Header().Set("X-RateLimit-Remaining", "0")
				c.Response().Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

				return cfg.OnLimitReached(c)
			}

			var newCount int
			if cfg.CountMode == config.CountAll {

				newCount = cfg.Store.Increment(key, resetTime)
			} else {

				newCount = count + 1
				cfg.Store.Set(key, newCount, resetTime)
			}

			remaining := max(cfg.Rate-newCount, 0)

			c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(cfg.Rate))
			c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			c.Response().Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

			err := next(c)

			if cfg.CountMode != config.CountAll {
				statusCode := c.Response().Status
				shouldCount := false

				switch cfg.CountMode {
				case config.CountFailures:
					shouldCount = statusCode >= 400
				case config.CountSuccess:
					shouldCount = statusCode < 400
				}

				if shouldCount {
					cfg.Store.Increment(key, resetTime)
				} else {

					if count > 0 {
						cfg.Store.Set(key, count, resetTime)
					} else {
						cfg.Store.Reset(key)
					}
				}
			}

			return err
		}
	}
}

func DefaultKeyGenerator(c echo.Context) string {

	realIP := c.RealIP()

	if realIP == "" || realIP == "unknown" {
		realIP = "fallback"
	}

	return "rate_limit:" + realIP
}

func SecureKeyGenerator(c echo.Context) string {
	realIP := c.RealIP()
	userAgent := c.Request().Header.Get("User-Agent")

	if realIP == "" || realIP == "unknown" {
		realIP = "fallback"
	}

	uaHash := simpleHash(userAgent)

	return fmt.Sprintf("rate_limit:%s:%s", realIP, uaHash)
}

func simpleHash(s string) string {
	if len(s) == 0 {
		return "none"
	}

	hash := uint32(0)
	for _, c := range s {
		hash = hash*31 + uint32(c)
	}

	return fmt.Sprintf("%x", hash%0xFFFFFF)
}

func DefaultOnLimitReached(c echo.Context) error {
	return echo.NewHTTPError(http.StatusTooManyRequests, "Too Many Requests")
}

func NewStore(rateLimitConfig *config.RateLimitConfig) Store {
	var store Store
	switch rateLimitConfig.Store {
	case "memory":
		fallthrough
	default:
		store = NewMemoryStore()
	}

	return store
}

func WithConfig(cfg *Config) echo.MiddlewareFunc {
	return Middleware(cfg)
}
