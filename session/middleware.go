package session

import (
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

const (
	sessionManagerKey = "session_manager"
	sessionServiceKey = "session_service"
)

func Middleware(manager *Manager) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if manager == nil {
				return next(c)
			}

			c.Set(sessionManagerKey, manager)

			var handlerErr error

			rw := &responseWriterWrapper{
				ResponseWriter: c.Response().Writer,
				echo:           c.Response(),
			}

			handler := manager.SessionManager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				ctx := context.WithValue(r.Context(), sessionManagerKey, manager)
				c.SetRequest(r.WithContext(ctx))
				c.Response().Writer = w
				handlerErr = next(c)
			}))

			handler.ServeHTTP(rw, c.Request())
			return handlerErr
		}
	}
}

// responseWriterWrapper wraps Echo's response writer to work with SCS
type responseWriterWrapper struct {
	http.ResponseWriter
	echo *echo.Response
}

func (w *responseWriterWrapper) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *responseWriterWrapper) Write(b []byte) (int, error) {
	return w.ResponseWriter.Write(b)
}

func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	if w.echo.Status == 0 {
		w.echo.Status = statusCode
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func GetManager(c echo.Context) *Manager {
	if manager := c.Get(sessionManagerKey); manager != nil {
		return manager.(*Manager)
	}
	return nil
}

func GetManagerFromContext(ctx context.Context) *Manager {
	if manager := ctx.Value(sessionManagerKey); manager != nil {
		return manager.(*Manager)
	}
	return nil
}

// SessionServiceMiddleware injects the session service and tracks session usage
func SessionServiceMiddleware(service SessionService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if service != nil {
				c.Set(sessionServiceKey, service)
			}

			err := next(c)

			if service != nil && IsAuthenticated(c) {
				manager := GetManager(c)
				if manager != nil {
					token := manager.Token(c.Request().Context())
					if token != "" {
						go func() {
							exists, err := service.SessionExists(token)
							if err == nil && !exists {
								userID := convertToUint(GetUserID(c))
								if userID > 0 {
									ipAddress := c.RealIP()
									userAgent := c.Request().UserAgent()
									expiresAt := time.Now().Add(manager.config.MaxAge)
									_ = service.TrackSession(userID, token, ipAddress, userAgent, expiresAt)
								}
							}
						}()
					}
				}
			}

			return err
		}
	}
}
