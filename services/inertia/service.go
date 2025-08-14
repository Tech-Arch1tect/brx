package inertia

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	gonertia "github.com/romsar/gonertia/v2"
)

type Service struct {
	config   *Config
	inertia  *gonertia.Inertia
	manifest *ViteManifest
}

type ViteManifest map[string]ViteManifestEntry

type ViteManifestEntry struct {
	File    string   `json:"file"`
	Src     string   `json:"src"`
	IsEntry bool     `json:"isEntry"`
	CSS     []string `json:"css,omitempty"`
	Assets  []string `json:"assets,omitempty"`
}

func New(cfg *Config) *Service {
	if !cfg.Enabled {
		return nil
	}

	return &Service{
		config: cfg,
	}
}

func (s *Service) InitializeFromFile(rootViewPath string) error {
	options := []gonertia.Option{}

	if s.config.Version != "" {
		options = append(options, gonertia.WithVersion(s.config.Version))
	}

	if s.config.SSREnabled {
		if s.config.SSRURL != "" {
			options = append(options, gonertia.WithSSR(s.config.SSRURL))
		} else {
			options = append(options, gonertia.WithSSR())
		}
	}

	options = append(options, gonertia.WithFlashProvider(NewSCSFlashProvider()))

	inertiaInstance, err := gonertia.NewFromFile(rootViewPath, options...)
	if err != nil {
		return err
	}

	s.inertia = inertiaInstance
	return nil
}

func (s *Service) ShareAssetData() {
	cssAssets, jsAssets, isDevelopment := s.getAssets()

	s.inertia.ShareTemplateData("cssAssets", cssAssets)
	s.inertia.ShareTemplateData("jsAssets", jsAssets)
	s.inertia.ShareTemplateData("isDevelopment", isDevelopment)
}

func (s *Service) InitializeFromFS(fs embed.FS, rootViewPath string) error {
	options := []gonertia.Option{}

	if s.config.Version != "" {
		options = append(options, gonertia.WithVersion(s.config.Version))
	}

	if s.config.SSREnabled {
		if s.config.SSRURL != "" {
			options = append(options, gonertia.WithSSR(s.config.SSRURL))
		} else {
			options = append(options, gonertia.WithSSR())
		}
	}

	options = append(options, gonertia.WithFlashProvider(NewSCSFlashProvider()))

	inertiaInstance, err := gonertia.NewFromFileFS(fs, rootViewPath, options...)
	if err != nil {
		return err
	}

	s.inertia = inertiaInstance
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
	if s.inertia == nil {
		return fmt.Errorf("inertia instance is nil")
	}

	return s.inertia.Render(c.Response(), c.Request(), component, props)
}

func (s *Service) Redirect(c echo.Context, url string) error {
	s.inertia.Redirect(c.Response(), c.Request(), url)
	return nil
}

func (s *Service) Location(c echo.Context, url string) error {
	s.inertia.Location(c.Response(), c.Request(), url)
	return nil
}

func (s *Service) Back(c echo.Context) error {
	s.inertia.Back(c.Response(), c.Request())
	return nil
}

func (s *Service) ShareProp(key string, value any) {
	s.inertia.ShareProp(key, value)
}

func (s *Service) ShareTemplateData(key string, value any) {
	s.inertia.ShareTemplateData(key, value)
}

func (s *Service) ShareTemplateFunc(name string, fn any) {
	s.inertia.ShareTemplateFunc(name, fn)
}

func (s *Service) LoadManifest(manifestPath string) error {
	if !s.config.Development {
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return err
		}

		var manifest ViteManifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			return err
		}

		s.manifest = &manifest
	}
	return nil
}

func (s *Service) getAssets() (cssAssets, jsAssets []string, isDevelopment bool) {
	if s.config.Development {
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
	}

	return cssAssets, jsAssets, false
}
