package inertiashared

import (
	"strings"

	"github.com/labstack/echo/v4"
	gonertia "github.com/romsar/gonertia/v2"
	"github.com/tech-arch1tect/brx/session"
)

type Config struct {
	AuthEnabled  bool
	FlashEnabled bool
	UserProvider UserProvider
}

type UserProvider interface {
	GetUser(userID uint) (any, error)
}

func Middleware() echo.MiddlewareFunc {
	return MiddlewareWithConfig(Config{
		AuthEnabled:  true,
		FlashEnabled: true,
		UserProvider: nil,
	})
}

func MiddlewareWithConfig(cfg Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			isStaticAsset := strings.HasPrefix(c.Request().URL.Path, "/build/") ||
				strings.HasPrefix(c.Request().URL.Path, "/assets/") ||
				strings.HasPrefix(c.Request().URL.Path, "/.well-known/")

			if !isStaticAsset {
				ctx := c.Request().Context()

				if cfg.AuthEnabled {
					isAuth := session.IsAuthenticated(c)
					userID := session.GetUserIDAsUint(c)

					ctx = gonertia.SetProp(ctx, "authenticated", isAuth)
					if isAuth && userID > 0 {
						ctx = gonertia.SetProp(ctx, "userID", userID)

						if cfg.UserProvider != nil {
							if user, err := cfg.UserProvider.GetUser(userID); err == nil && user != nil {
								ctx = gonertia.SetProp(ctx, "currentUser", user)
							}
						}
					}
				}

				if cfg.FlashEnabled {
					if flashMessages := session.GetFlashMessages(c); flashMessages != nil {
						ctx = gonertia.SetProp(ctx, "flashMessages", flashMessages)
					}
				}

				c.SetRequest(c.Request().WithContext(ctx))
			}

			return next(c)
		}
	}
}
