package jwt

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/tech-arch1tect/brx/services/jwt"
)

const (
	UserIDKey = "_jwt_user_id"
	ClaimsKey = "_jwt_claims"
)

func RequireJWT(jwtService *jwt.Service) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header required")
			}

			if !strings.HasPrefix(authHeader, "Bearer ") {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization header format")
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "JWT token required")
			}

			claims, err := jwtService.ValidateToken(tokenString)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authentication failed")
			}

			c.Set(UserIDKey, claims.UserID)
			c.Set(ClaimsKey, claims)

			return next(c)
		}
	}
}

func GetUserID(c echo.Context) uint {
	if userID, ok := c.Get(UserIDKey).(uint); ok {
		return userID
	}
	return 0
}

func GetClaims(c echo.Context) *jwt.Claims {
	if claims, ok := c.Get(ClaimsKey).(*jwt.Claims); ok {
		return claims
	}
	return nil
}
