package inertia

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	gonertia "github.com/romsar/gonertia/v2"
	"github.com/tech-arch1tect/brx/middleware/inertiashared"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/zap"
)

type Service struct {
	config   *Config
	inertia  *gonertia.Inertia
	manifest *ViteManifest
	logger   *logging.Service
}

type ViteManifest map[string]ViteManifestEntry

type ViteManifestEntry struct {
	File    string   `json:"file"`
	Src     string   `json:"src"`
	IsEntry bool     `json:"isEntry"`
	CSS     []string `json:"css,omitempty"`
	Assets  []string `json:"assets,omitempty"`
}

func New(cfg *Config, logger *logging.Service) *Service {
	if !cfg.Enabled {
		if logger != nil {
			logger.Debug("Inertia service disabled in configuration")
		}
		return nil
	}

	if logger != nil {
		logger.Info("initializing Inertia service",
			zap.Bool("ssr_enabled", cfg.SSREnabled),
			zap.String("ssr_url", cfg.SSRURL),
			zap.String("version", cfg.Version),
			zap.Bool("development_mode", cfg.Development))
	}

	return &Service{
		config: cfg,
		logger: logger,
	}
}

func (s *Service) InitializeFromFile(rootViewPath string) error {
	if s.logger != nil {
		s.logger.Info("initializing Inertia from file",
			zap.String("root_view_path", rootViewPath),
			zap.Bool("ssr_enabled", s.config.SSREnabled),
			zap.String("version", s.config.Version))
	}

	startTime := time.Now()
	options := []gonertia.Option{}

	if s.config.Version != "" {
		options = append(options, gonertia.WithVersion(s.config.Version))
		if s.logger != nil {
			s.logger.Debug("using Inertia version", zap.String("version", s.config.Version))
		}
	}

	if s.config.SSREnabled {
		if s.config.SSRURL != "" {
			options = append(options, gonertia.WithSSR(s.config.SSRURL))
			if s.logger != nil {
				s.logger.Info("enabling SSR with custom URL", zap.String("ssr_url", s.config.SSRURL))
			}
		} else {
			options = append(options, gonertia.WithSSR())
			if s.logger != nil {
				s.logger.Info("enabling SSR with default configuration")
			}
		}
	} else if s.logger != nil {
		s.logger.Debug("SSR disabled")
	}

	options = append(options, gonertia.WithFlashProvider(NewSCSFlashProvider()))
	if s.logger != nil {
		s.logger.Debug("using SCS flash provider for Inertia")
	}

	inertiaInstance, err := gonertia.NewFromFile(rootViewPath, options...)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to initialize Inertia from file",
				zap.Error(err),
				zap.String("root_view_path", rootViewPath),
				zap.Duration("initialization_duration", time.Since(startTime)))
		}
		return err
	}

	s.inertia = inertiaInstance

	if s.logger != nil {
		s.logger.Info("Inertia service initialized successfully from file",
			zap.String("root_view_path", rootViewPath),
			zap.Duration("initialization_duration", time.Since(startTime)))
	}

	return nil
}

func (s *Service) ShareAssetData() {
	if s.logger != nil {
		s.logger.Debug("sharing asset data with Inertia templates")
	}

	cssAssets, jsAssets, isDevelopment := s.getAssets()

	s.inertia.ShareTemplateData("cssAssets", cssAssets)
	s.inertia.ShareTemplateData("jsAssets", jsAssets)
	s.inertia.ShareTemplateData("isDevelopment", isDevelopment)

	if s.logger != nil {
		s.logger.Debug("asset data shared successfully",
			zap.Int("css_assets_count", len(cssAssets)),
			zap.Int("js_assets_count", len(jsAssets)),
			zap.Bool("development_mode", isDevelopment))
	}
}

func (s *Service) InitializeFromFS(fs embed.FS, rootViewPath string) error {
	if s.logger != nil {
		s.logger.Info("initializing Inertia from embedded filesystem",
			zap.String("root_view_path", rootViewPath),
			zap.Bool("ssr_enabled", s.config.SSREnabled))
	}

	startTime := time.Now()
	options := []gonertia.Option{}

	if s.config.Version != "" {
		options = append(options, gonertia.WithVersion(s.config.Version))
		if s.logger != nil {
			s.logger.Debug("using Inertia version", zap.String("version", s.config.Version))
		}
	}

	if s.config.SSREnabled {
		if s.config.SSRURL != "" {
			options = append(options, gonertia.WithSSR(s.config.SSRURL))
			if s.logger != nil {
				s.logger.Info("enabling SSR with custom URL", zap.String("ssr_url", s.config.SSRURL))
			}
		} else {
			options = append(options, gonertia.WithSSR())
			if s.logger != nil {
				s.logger.Info("enabling SSR with default configuration")
			}
		}
	}

	options = append(options, gonertia.WithFlashProvider(NewSCSFlashProvider()))

	inertiaInstance, err := gonertia.NewFromFileFS(fs, rootViewPath, options...)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to initialize Inertia from embedded filesystem",
				zap.Error(err),
				zap.String("root_view_path", rootViewPath),
				zap.Duration("initialization_duration", time.Since(startTime)))
		}
		return err
	}

	s.inertia = inertiaInstance

	if s.logger != nil {
		s.logger.Info("Inertia service initialized successfully from embedded filesystem",
			zap.String("root_view_path", rootViewPath),
			zap.Duration("initialization_duration", time.Since(startTime)))
	}

	return nil
}

func (s *Service) Instance() *gonertia.Inertia {
	return s.inertia
}

func (s *Service) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			handler := s.inertia.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)

				if err := next(c); err != nil {
					c.Error(err)
				}
			}))

			handler.ServeHTTP(c.Response(), c.Request())
			return nil
		}
	}
}

func (s *Service) Render(c echo.Context, component string, props gonertia.Props) error {
	if s.logger != nil {
		s.logger.Debug("rendering Inertia component",
			zap.String("component", component),
			zap.String("method", c.Request().Method),
			zap.String("path", c.Request().URL.Path))
	}

	if s.inertia == nil {
		if s.logger != nil {
			s.logger.Error("Inertia render failed - service not initialized",
				zap.String("component", component))
		}
		return fmt.Errorf("inertia instance is nil")
	}

	startTime := time.Now()
	err := s.inertia.Render(c.Response(), c.Request(), component, props)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("Inertia component render failed",
				zap.Error(err),
				zap.String("component", component),
				zap.Duration("render_duration", time.Since(startTime)))
		}
		return err
	}

	if s.logger != nil {
		s.logger.Debug("Inertia component rendered successfully",
			zap.String("component", component),
			zap.Duration("render_duration", time.Since(startTime)))
	}

	return nil
}

func (s *Service) Redirect(c echo.Context, url string) error {
	method := c.Request().Method

	if s.logger != nil {
		s.logger.Debug("performing Inertia redirect",
			zap.String("url", url),
			zap.String("method", method),
			zap.String("from_path", c.Request().URL.Path))
	}

	if method == "PUT" || method == "PATCH" || method == "DELETE" {
		c.Response().Header().Set("Location", url)
		c.Response().WriteHeader(303)
		if s.logger != nil {
			s.logger.Debug("redirect performed with 303 status for non-GET method",
				zap.String("url", url),
				zap.String("method", method))
		}
		return nil
	}

	s.inertia.Redirect(c.Response(), c.Request(), url)
	if s.logger != nil {
		s.logger.Debug("Inertia redirect performed",
			zap.String("url", url),
			zap.String("method", method))
	}
	return nil
}

func (s *Service) ApplyMiddlewareToGroup(group *echo.Group, userProvider any) {
	if s.inertia == nil {
		if s.logger != nil {
			s.logger.Warn("cannot apply Inertia middleware - service not initialized")
		}
		return
	}

	if s.logger != nil {
		s.logger.Debug("applying Inertia middleware to route group",
			zap.Bool("has_user_provider", userProvider != nil))
	}

	group.Use(s.Middleware())

	middlewareConfig := inertiashared.Config{
		AuthEnabled:  true,
		FlashEnabled: true,
		UserProvider: nil,
	}

	if provider, ok := userProvider.(inertiashared.UserProvider); ok {
		middlewareConfig.UserProvider = provider
		if s.logger != nil {
			s.logger.Debug("user provider configured for Inertia middleware")
		}
	} else if s.logger != nil {
		s.logger.Debug("no user provider available for Inertia middleware")
	}

	group.Use(inertiashared.MiddlewareWithConfig(middlewareConfig))

	if s.logger != nil {
		s.logger.Debug("Inertia middleware applied successfully")
	}
}

func (s *Service) Location(c echo.Context, url string) error {
	if s.logger != nil {
		s.logger.Debug("performing Inertia location redirect",
			zap.String("url", url),
			zap.String("from_path", c.Request().URL.Path))
	}

	s.inertia.Location(c.Response(), c.Request(), url)
	return nil
}

func (s *Service) Back(c echo.Context) error {
	method := c.Request().Method
	referer := c.Request().Header.Get("Referer")

	if s.logger != nil {
		s.logger.Debug("performing Inertia back navigation",
			zap.String("method", method),
			zap.String("referer", referer),
			zap.String("current_path", c.Request().URL.Path))
	}

	if method == "PUT" || method == "PATCH" || method == "DELETE" {
		if referer != "" {
			c.Response().Header().Set("Location", referer)
			c.Response().WriteHeader(303)
			if s.logger != nil {
				s.logger.Debug("back navigation performed with 303 status",
					zap.String("referer", referer))
			}
			return nil
		}
	}

	s.inertia.Back(c.Response(), c.Request())
	if s.logger != nil {
		s.logger.Debug("Inertia back navigation performed")
	}
	return nil
}

func (s *Service) ShareProp(key string, value any) {
	if s.logger != nil {
		s.logger.Debug("sharing Inertia prop", zap.String("key", key))
	}
	s.inertia.ShareProp(key, value)
}

func (s *Service) ShareTemplateData(key string, value any) {
	if s.logger != nil {
		s.logger.Debug("sharing Inertia template data", zap.String("key", key))
	}
	s.inertia.ShareTemplateData(key, value)
}

func (s *Service) ShareTemplateFunc(name string, fn any) {
	if s.logger != nil {
		s.logger.Debug("sharing Inertia template function", zap.String("name", name))
	}
	s.inertia.ShareTemplateFunc(name, fn)
}

func (s *Service) LoadManifest(manifestPath string) error {
	if s.config.Development {
		if s.logger != nil {
			s.logger.Debug("skipping manifest loading in development mode")
		}
		return nil
	}

	if s.logger != nil {
		s.logger.Info("loading Vite manifest", zap.String("manifest_path", manifestPath))
	}

	startTime := time.Now()
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to read Vite manifest file",
				zap.Error(err),
				zap.String("manifest_path", manifestPath))
		}
		return err
	}

	var manifest ViteManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		if s.logger != nil {
			s.logger.Error("failed to parse Vite manifest JSON",
				zap.Error(err),
				zap.String("manifest_path", manifestPath))
		}
		return err
	}

	s.manifest = &manifest

	// Count manifest entries
	entryCount := 0
	for _, entry := range manifest {
		if entry.IsEntry {
			entryCount++
		}
	}

	if s.logger != nil {
		s.logger.Info("Vite manifest loaded successfully",
			zap.String("manifest_path", manifestPath),
			zap.Int("total_entries", len(manifest)),
			zap.Int("entry_points", entryCount),
			zap.Duration("load_duration", time.Since(startTime)))
	}

	return nil
}

func (s *Service) getAssets() (cssAssets, jsAssets []string, isDevelopment bool) {
	if s.config.Development {
		if s.logger != nil {
			s.logger.Debug("returning development mode assets (empty)")
		}
		return nil, nil, true
	}

	if s.manifest != nil {
		for _, entry := range *s.manifest {
			if entry.IsEntry {
				for _, css := range entry.CSS {
					cssAssets = append(cssAssets, "/build/"+css)
				}
				if entry.File != "" {
					jsAssets = append(jsAssets, "/build/"+entry.File)
				}
			}
		}
		if s.logger != nil {
			s.logger.Debug("production assets collected from manifest",
				zap.Int("css_assets", len(cssAssets)),
				zap.Int("js_assets", len(jsAssets)))
		}
	} else if s.logger != nil {
		s.logger.Debug("no manifest available for asset collection")
	}

	return cssAssets, jsAssets, false
}
