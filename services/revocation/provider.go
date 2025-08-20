package revocation

import (
	"fmt"

	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/jwt"
	"github.com/tech-arch1tect/brx/services/logging"
	"github.com/tech-arch1tect/brx/session"
	"go.uber.org/fx"
)

func ProvideStore(cfg *config.Config, logger *logging.Service) (Store, error) {
	if !cfg.Revocation.Enabled {
		return nil, nil
	}

	switch cfg.Revocation.Store {
	case "memory":
		return NewMemoryStore(), nil
	default:
		return nil, fmt.Errorf("unsupported revocation store type: %s", cfg.Revocation.Store)
	}
}

func ProvideRevocationService(cfg *config.Config, logger *logging.Service) (*Service, error) {
	if !cfg.Revocation.Enabled {
		return nil, nil
	}

	store, err := ProvideStore(cfg, logger)
	if err != nil {
		return nil, err
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

var Module = fx.Options(
	fx.Provide(ProvideRevocationService),
	fx.Provide(ProvideRevocationAsSessionInterface),
	fx.Provide(ProvideRevocationAsJWTInterface),
	fx.Invoke(StartCleanupWorkerIfEnabled),
)
