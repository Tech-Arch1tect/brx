package rememberme

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/middleware/jwtshared"
	"github.com/tech-arch1tect/brx/services/auth"
	"github.com/tech-arch1tect/brx/services/logging"
	"github.com/tech-arch1tect/brx/services/totp"
	"github.com/tech-arch1tect/brx/session"
	"go.uber.org/zap"
)

type Config struct {
	AuthService  *auth.Service
	UserProvider jwtshared.UserProvider
	TOTPService  *totp.Service
	Logger       *logging.Service
}

func Middleware(cfg Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if session.IsAuthenticated(c) {
				return next(c)
			}

			if cfg.AuthService == nil || !cfg.AuthService.IsRememberMeEnabled() {
				return next(c)
			}

			cookie, err := c.Cookie("remember_me")
			if err != nil || cookie.Value == "" {
				return next(c)
			}

			rememberToken, err := cfg.AuthService.ValidateRememberMeToken(cookie.Value)
			if err != nil {
				if cfg.Logger != nil {
					cfg.Logger.Debug("remember me token validation failed",
						zap.Error(err))
				}
				clearRememberCookie(c, cfg.AuthService)
				return next(c)
			}

			if cfg.UserProvider != nil {
				if _, err := cfg.UserProvider.GetUser(rememberToken.UserID); err != nil {
					if cfg.Logger != nil {
						cfg.Logger.Warn("remember me user not found",
							zap.Uint("user_id", rememberToken.UserID),
							zap.Error(err))
					}
					clearRememberCookie(c, cfg.AuthService)
					return next(c)
				}
			}

			session.LoginWithTOTPService(c, rememberToken.UserID, cfg.TOTPService)

			if cfg.TOTPService != nil && cfg.TOTPService.IsUserTOTPEnabled(rememberToken.UserID) {
				session.SetTOTPVerified(c, true)
			}

			if cfg.AuthService.ShouldRotateRememberMeToken() {
				if newToken, err := cfg.AuthService.RotateRememberMeToken(cookie.Value); err == nil {
					setRememberCookie(c, cfg.AuthService, newToken.Token, newToken.ExpiresAt)
				} else if cfg.Logger != nil {
					cfg.Logger.Error("failed to rotate remember me token",
						zap.Error(err))
				}
			}

			return next(c)
		}
	}
}

func setRememberCookie(c echo.Context, svc *auth.Service, token string, expiresAt time.Time) {
	cookie := &http.Cookie{
		Name:     "remember_me",
		Value:    token,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   svc.GetRememberMeCookieSecure(),
		SameSite: mapSameSite(svc.GetRememberMeCookieSameSite()),
		Path:     "/",
	}
	c.SetCookie(cookie)
}

func clearRememberCookie(c echo.Context, svc *auth.Service) {
	cookie := &http.Cookie{
		Name:     "remember_me",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   svc.GetRememberMeCookieSecure(),
		SameSite: mapSameSite(svc.GetRememberMeCookieSameSite()),
		Path:     "/",
	}
	c.SetCookie(cookie)
}

func mapSameSite(setting string) http.SameSite {
	switch setting {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
