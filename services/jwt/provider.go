package jwt

import (
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/fx"
)

func NewJWTService(cfg *config.Config, logger *logging.Service) *Service {
	return NewService(cfg, logger)
}

type OptionalRevocationService struct {
	fx.In
	RevocationService RevocationService `optional:"true"`
}

func WireRevocationService(jwtSvc *Service, optRevocationSvc OptionalRevocationService) {
	if jwtSvc != nil && optRevocationSvc.RevocationService != nil {
		jwtSvc.SetRevocationService(optRevocationSvc.RevocationService)
	}
}

var Options = fx.Options(
	fx.Provide(NewJWTService),
	fx.Invoke(WireRevocationService),
)
