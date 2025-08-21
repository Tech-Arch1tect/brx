package session

import (
	"fmt"
	"net/http"

	"github.com/alexedwards/scs/v2"
	"github.com/tech-arch1tect/brx/config"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

type Manager struct {
	*scs.SessionManager
	config config.SessionConfig
}

type Options struct {
	Store scs.Store
}

func ProvideSessionManager(cfg *config.Config, opts *Options, db *gorm.DB) (*Manager, error) {
	if !cfg.Session.Enabled {
		return nil, nil
	}

	sessionManager := scs.New()

	var store scs.Store
	var err error

	if opts != nil && opts.Store != nil {
		store = opts.Store
	} else {
		switch cfg.Session.Store {
		case "memory":
			store = NewMemoryStore()
		case "database":
			if db == nil {
				return nil, fmt.Errorf("database store requires database to be enabled")
			}
			store, err = NewDatabaseStore(db)
			if err != nil {
				return nil, fmt.Errorf("failed to create database session store: %w", err)
			}
		default:
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

	return &Manager{
		SessionManager: sessionManager,
		config:         cfg.Session,
	}, nil
}

func ProvideSessionService(db *gorm.DB, manager *Manager) SessionService {
	if db == nil || manager == nil {
		return nil
	}
	return NewSessionService(db, manager)
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
