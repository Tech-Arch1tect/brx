package inertiacsrf

import (
	"context"
	"strings"

	"github.com/labstack/echo/v4"
	gonertia "github.com/romsar/gonertia/v2"
	"github.com/tech-arch1tect/brx/config"
)

func Middleware(cfg *config.Config) echo.MiddlewareFunc {
	if !cfg.CSRF.Enabled {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return next
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := c.Get(cfg.CSRF.ContextKey)

			// Exclude static assets from CSRF token injection
			isStaticAsset := strings.HasPrefix(c.Request().URL.Path, "/build/") ||
				strings.HasPrefix(c.Request().URL.Path, "/assets/") ||
				strings.HasPrefix(c.Request().URL.Path, "/.well-known/")

			if !isStaticAsset && token != nil {
				ctx := c.Request().Context()
				ctx = gonertia.SetProp(ctx, "csrfToken", token.(string))
				c.SetRequest(c.Request().WithContext(ctx))
			}

			return next(c)
		}
	}
}

func inertiaCSRFContext(ctx context.Context, token string) context.Context {
	return gonertia.SetProp(ctx, "csrfToken", token)
}
