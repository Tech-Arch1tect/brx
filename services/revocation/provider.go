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
		return nil, nil
	}

	switch cfg.Revocation.Store {
	case "memory":
		if optDB.DB != nil {
			if err := optDB.DB.AutoMigrate(&RevokedToken{}); err != nil {
				logger.Error("failed to migrate revoked tokens table", zap.Error(err))
				return NewMemoryStore(), nil
			}
			return NewMemoryStoreWithDB(optDB.DB, logger), nil
		}
		return NewMemoryStore(), nil
	default:
		return nil, fmt.Errorf("unsupported revocation store type: %s", cfg.Revocation.Store)
	}
}

func ProvideRevocationService(cfg *config.Config, logger *logging.Service, optDB OptionalDB, store Store) (*Service, error) {
	if !cfg.Revocation.Enabled {
		return nil, nil
	}

	if store == nil {
		return nil, nil
	}

	return NewService(cfg, store, logger), nil
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

func StartCleanupWorkerIfEnabled(cfg *config.Config, optRevocationSvc OptionalRevocationService) {
	if optRevocationSvc.RevocationService != nil {
		optRevocationSvc.RevocationService.StartCleanupWorker(cfg.Revocation.CleanupPeriod)
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
