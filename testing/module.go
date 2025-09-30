package e2etesting

import (
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Provide(ProvideE2EApp),
	fx.Provide(ProvideTestConfig),
	fx.Provide(ProvideHTTPClient),
)
