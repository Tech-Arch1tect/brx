package revocation

import (
	"context"
	"fmt"

	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/jwt"
	"github.com/tech-arch1tect/brx/services/logging"
	"github.com/tech-arch1tect/brx/session"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type OptionalDB struct {
	fx.In
	DB *gorm.DB `optional:"true"`
}

func ProvideStore(cfg *config.Config, logger *logging.Service, optDB OptionalDB) (Store, error) {
	if !cfg.Revocation.Enabled {
		if logger != nil {
			logger.Debug("JWT revocation store disabled in configuration")
		}
		return nil, nil
	}

	if logger != nil {
		logger.Info("initializing JWT revocation store",
			zap.String("store_type", cfg.Revocation.Store),
			zap.Bool("database_available", optDB.DB != nil))
	}

	switch cfg.Revocation.Store {
	case "memory":
		if optDB.DB != nil {
			if logger != nil {
				logger.Debug("setting up memory store with database persistence")
			}
			if err := optDB.DB.AutoMigrate(&RevokedToken{}); err != nil {
				if logger != nil {
					logger.Error("failed to migrate revoked tokens table - falling back to memory-only store", zap.Error(err))
				}
				return NewMemoryStore(), nil
			}
			if logger != nil {
				logger.Info("memory store with database persistence initialized successfully")
			}
			return NewMemoryStoreWithDB(optDB.DB, logger), nil
		}
		if logger != nil {
			logger.Info("memory-only revocation store initialized (no database available)")
		}
		return NewMemoryStore(), nil
	default:
		if logger != nil {
			logger.Error("unsupported revocation store type",
				zap.String("store_type", cfg.Revocation.Store),
				zap.Strings("supported_types", []string{"memory"}))
		}
		return nil, fmt.Errorf("unsupported revocation store type: %s", cfg.Revocation.Store)
	}
}

func ProvideRevocationService(cfg *config.Config, logger *logging.Service, optDB OptionalDB, store Store) (*Service, error) {
	if !cfg.Revocation.Enabled {
		if logger != nil {
			logger.Debug("JWT revocation service disabled in configuration")
		}
		return nil, nil
	}

	if store == nil {
		if logger != nil {
			logger.Warn("JWT revocation service cannot start - no store available")
		}
		return nil, nil
	}

	service := NewService(cfg, store, logger)
	if logger != nil {
		logger.Info("JWT revocation service initialized successfully")
	}

	return service, nil
}

func ProvideRevocationAsSessionInterface(svc *Service) session.JWTRevocationService {
	return svc
}

func ProvideRevocationAsJWTInterface(svc *Service) jwt.RevocationService {
	return svc
}

type OptionalRevocationService struct {
	fx.In
	RevocationService *Service `optional:"true"`
}

func StartCleanupWorkerIfEnabled(cfg *config.Config, optRevocationSvc OptionalRevocationService, logger *logging.Service) {
	if optRevocationSvc.RevocationService != nil {
		if logger != nil {
			logger.Debug("starting JWT revocation cleanup worker",
				zap.Duration("cleanup_period", cfg.Revocation.CleanupPeriod))
		}
		optRevocationSvc.RevocationService.StartCleanupWorker(cfg.Revocation.CleanupPeriod)
	} else if logger != nil {
		logger.Debug("JWT revocation cleanup worker not started - service not available")
	}
}

type OptionalRevocationStore struct {
	fx.In
	Store Store `optional:"true"`
}

func SetupRevocationPersistence(lc fx.Lifecycle, cfg *config.Config, logger *logging.Service, optStore OptionalRevocationStore) {
	if !cfg.Revocation.Enabled || optStore.Store == nil {
		return
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			logger.Info("attempting to load revoked tokens from database on startup")
			if err := optStore.Store.LoadFromDatabase(); err != nil {
				logger.Error("failed to load revoked tokens from database on startup", zap.Error(err))
				return err
			}
			logger.Info("completed loading revoked tokens from database on startup")
			return nil
		},
		OnStop: func(ctx context.Context) error {
			if err := optStore.Store.SaveToDatabase(); err != nil {
				logger.Error("failed to save revoked tokens to database on shutdown", zap.Error(err))
				return err
			}
			logger.Info("saved revoked tokens to database on shutdown")
			return nil
		},
	})
}

var Module = fx.Options(
	fx.Provide(ProvideStore),
	fx.Provide(ProvideRevocationService),
	fx.Provide(ProvideRevocationAsSessionInterface),
	fx.Provide(ProvideRevocationAsJWTInterface),
	fx.Invoke(StartCleanupWorkerIfEnabled),
	fx.Invoke(SetupRevocationPersistence),
)
