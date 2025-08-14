package session

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"
)

const sessionManagerKey = "session_manager"

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
