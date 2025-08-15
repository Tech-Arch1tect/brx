package csrf

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/tech-arch1tect/brx/config"
)

func Middleware(cfg *config.CSRFConfig) echo.MiddlewareFunc {
	if !cfg.Enabled {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return next
		}
	}

	var sameSite http.SameSite
	switch cfg.CookieSameSite {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "lax":
		sameSite = http.SameSiteLaxMode
	case "none":
		sameSite = http.SameSiteNoneMode
	default:
		sameSite = http.SameSiteDefaultMode
	}

	return middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLength:    cfg.TokenLength,
		TokenLookup:    cfg.TokenLookup,
		ContextKey:     cfg.ContextKey,
		CookieName:     cfg.CookieName,
		CookieDomain:   cfg.CookieDomain,
		CookiePath:     cfg.CookiePath,
		CookieMaxAge:   cfg.CookieMaxAge,
		CookieSecure:   cfg.CookieSecure,
		CookieHTTPOnly: cfg.CookieHTTPOnly,
		CookieSameSite: sameSite,
	})
}

func WithConfig(cfg *config.CSRFConfig) echo.MiddlewareFunc {
	return Middleware(cfg)
}

func GetToken(c echo.Context) string {
	if token := c.Get("csrf"); token != nil {
		return token.(string)
	}
	return ""
}
