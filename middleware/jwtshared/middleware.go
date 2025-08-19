package jwtshared

import (
	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/middleware/jwt"
)

type Config struct {
	UserProvider UserProvider
}

type UserProvider interface {
	GetUser(userID uint) (any, error)
}

func Middleware() echo.MiddlewareFunc {
	return MiddlewareWithConfig(Config{
		UserProvider: nil,
	})
}

func MiddlewareWithConfig(cfg Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID := jwt.GetUserID(c)

			if userID > 0 && cfg.UserProvider != nil {
				if user, err := cfg.UserProvider.GetUser(userID); err == nil && user != nil {
					c.Set("currentUser", user)
				}
			}

			return next(c)
		}
	}
}

func GetCurrentUser(c echo.Context) any {
	return c.Get("currentUser")
}
