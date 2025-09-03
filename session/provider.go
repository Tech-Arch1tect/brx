package session

import (
	"fmt"
	"net/http"

	"github.com/alexedwards/scs/v2"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Manager struct {
	*scs.SessionManager
	config config.SessionConfig
}

type Options struct {
	Store scs.Store
}

func ProvideSessionManager(cfg *config.Config, opts *Options, db *gorm.DB, logger *logging.Service) (*Manager, error) {
	if !cfg.Session.Enabled {
		if logger != nil {
			logger.Debug("session manager disabled in configuration")
		}
		return nil, nil
	}

	if logger != nil {
		logger.Info("initializing session manager",
			zap.String("store", cfg.Session.Store),
			zap.Duration("max_age", cfg.Session.MaxAge),
			zap.String("cookie_name", cfg.Session.Name),
			zap.Bool("secure", cfg.Session.Secure))
	}

	sessionManager := scs.New()

	var store scs.Store
	var err error

	if opts != nil && opts.Store != nil {
		store = opts.Store
	} else {
		switch cfg.Session.Store {
		case "memory":
			if logger != nil {
				logger.Debug("using memory session store")
			}
			store = NewMemoryStore()
		case "database":
			if db == nil {
				if logger != nil {
					logger.Error("database store requested but database not available")
				}
				return nil, fmt.Errorf("database store requires database to be enabled")
			}
			if logger != nil {
				logger.Debug("using database session store")
			}
			store, err = NewDatabaseStore(db)
			if err != nil {
				if logger != nil {
					logger.Error("failed to create database session store",
						zap.Error(err))
				}
				return nil, fmt.Errorf("failed to create database session store: %w", err)
			}
		default:
			if logger != nil {
				logger.Error("unsupported session store requested",
					zap.String("store", cfg.Session.Store),
					zap.Strings("supported_stores", []string{"memory", "database"}))
			}
			return nil, fmt.Errorf("unsupported session store: %s", cfg.Session.Store)
		}
	}

	sessionManager.Store = store
	sessionManager.Lifetime = cfg.Session.MaxAge
	sessionManager.IdleTimeout = cfg.Session.MaxAge
	sessionManager.Cookie.Name = cfg.Session.Name
	sessionManager.Cookie.Path = cfg.Session.Path
	sessionManager.Cookie.Domain = cfg.Session.Domain
	sessionManager.Cookie.Secure = cfg.Session.Secure
	sessionManager.Cookie.HttpOnly = cfg.Session.HttpOnly

	switch cfg.Session.SameSite {
	case "strict":
		sessionManager.Cookie.SameSite = http.SameSiteStrictMode
	case "lax":
		sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	case "none":
		sessionManager.Cookie.SameSite = http.SameSiteNoneMode
	default:
		sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	}

	manager := &Manager{
		SessionManager: sessionManager,
		config:         cfg.Session,
	}

	if logger != nil {
		logger.Info("session manager initialized successfully",
			zap.String("store", cfg.Session.Store),
			zap.String("cookie_name", cfg.Session.Name),
			zap.String("same_site", cfg.Session.SameSite))
	}

	return manager, nil
}

func ProvideSessionService(db *gorm.DB, manager *Manager, logger *logging.Service) SessionService {
	if db == nil || manager == nil {
		if logger != nil {
			logger.Debug("session service not available - database or manager missing")
		}
		return nil
	}
	return NewSessionService(db, manager, logger)
}

type OptionalJWTService struct {
	fx.In
	JWTService JWTRevocationService `optional:"true"`
}

type OptionalRefreshTokenService struct {
	fx.In
	RefreshTokenService RefreshTokenRevocationService `optional:"true"`
}

func WireJWTRevocationService(sessionSvc SessionService, optJWTSvc OptionalJWTService) {
	if sessionSvc != nil && optJWTSvc.JWTService != nil {
		if svc, ok := sessionSvc.(*sessionService); ok {
			svc.SetJWTRevocationService(optJWTSvc.JWTService)
		}
	}
}

func WireRefreshTokenRevocationService(sessionSvc SessionService, optRefreshSvc OptionalRefreshTokenService) {
	if sessionSvc != nil && optRefreshSvc.RefreshTokenService != nil {
		if svc, ok := sessionSvc.(*sessionService); ok {
			svc.SetRefreshTokenRevocationService(optRefreshSvc.RefreshTokenService)
		}
	}
}

var Module = fx.Module("session",
	fx.Provide(ProvideSessionManager),
	fx.Provide(ProvideSessionService),
	fx.Invoke(WireJWTRevocationService),
	fx.Invoke(WireRefreshTokenRevocationService),
)
