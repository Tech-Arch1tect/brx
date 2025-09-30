package e2etesting

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/tech-arch1tect/brx/app"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/auth"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

type E2EApp struct {
	App        *app.App
	TestServer *httptest.Server
	BaseURL    string
	Config     *config.Config
	DB         *gorm.DB
	AuthSvc    *auth.Service
	cleanup    func()
}

type TestConfig struct {
	DatabaseURL     string
	DisableLogging  bool
	EnableDebugMode bool
	TestPort        int
	OverrideConfig  func(*config.Config) *config.Config
}

type HTTPClient struct {
	Client  *http.Client
	BaseURL string
}

func ProvideTestConfig() *TestConfig {
	return &TestConfig{
		DatabaseURL:     ":memory:",
		DisableLogging:  true,
		EnableDebugMode: true,
		TestPort:        0,
	}
}

func ProvideHTTPClient(e2eApp *E2EApp) *HTTPClient {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	baseURL := "http://localhost:8080"
	if e2eApp != nil && e2eApp.BaseURL != "" {
		baseURL = e2eApp.BaseURL
	}

	return &HTTPClient{
		Client:  client,
		BaseURL: baseURL,
	}
}

func ProvideE2EApp(testConfig *TestConfig, logger *logging.Service) (*E2EApp, error) {

	e2eApp := &E2EApp{
		Config: createTestConfig(testConfig),
	}

	return e2eApp, nil
}

func createTestConfig(testConfig *TestConfig) *config.Config {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "Test App",
			URL:  "http://localhost:8080",
		},
		Server: config.ServerConfig{
			Host: "localhost",
			Port: "8081",
		},
		Database: config.DatabaseConfig{
			Driver:      "sqlite",
			DSN:         testConfig.DatabaseURL,
			AutoMigrate: true,
		},
		Log: config.LogConfig{
			Level:  "panic",
			Format: "json",
			Output: "stdout",
		},
		Session: config.SessionConfig{
			Enabled:  true,
			Store:    "memory",
			Name:     "test_session",
			MaxAge:   time.Hour,
			Secure:   false,
			HttpOnly: true,
			SameSite: "lax",
		},
		Auth: config.AuthConfig{
			MinLength:                    8,
			RequireUpper:                 false,
			RequireLower:                 false,
			RequireNumber:                false,
			RequireSpecial:               false,
			PasswordResetEnabled:         true,
			PasswordResetTokenLength:     32,
			PasswordResetExpiry:          time.Hour,
			EmailVerificationEnabled:     true,
			EmailVerificationTokenLength: 32,
			EmailVerificationExpiry:      time.Hour,
			RememberMeEnabled:            true,
			RememberMeTokenLength:        32,
			RememberMeExpiry:             24 * time.Hour,
			RememberMeCookieSecure:       false,
			RememberMeCookieSameSite:     "lax",
		},
		JWT: config.JWTConfig{
			SecretKey:    "test-secret-key-for-testing-only",
			AccessExpiry: time.Hour,
			Issuer:       "test-issuer",
			Algorithm:    "HS256",
		},
		Inertia: config.InertiaConfig{
			Enabled:     true,
			RootView:    "app.html",
			Development: true,
		},
		CSRF: config.CSRFConfig{
			Enabled: false,
		},
		Mail: config.MailConfig{
			FromAddress: "test@example.com",
			FromName:    "Test App",
			Host:        "localhost",
			Port:        587,
		},
	}

	if testConfig.DisableLogging {
		cfg.Log.Level = "fatal"
	}
	if testConfig.EnableDebugMode {
		cfg.Log.Level = "debug"
	}
	if testConfig.TestPort > 0 {
		cfg.Server.Port = fmt.Sprintf("%d", testConfig.TestPort)
	}

	if testConfig.OverrideConfig != nil {
		cfg = testConfig.OverrideConfig(cfg)
	}

	return cfg
}

func (e *E2EApp) Start(ctx context.Context) error {
	if e.App == nil {
		return fmt.Errorf("application not built - call BuildTestApp first")
	}

	if err := e.App.Start(); err != nil {
		return fmt.Errorf("failed to start test app: %w", err)
	}

	time.Sleep(200 * time.Millisecond)

	e.BaseURL = fmt.Sprintf("http://localhost:%s", e.Config.Server.Port)

	return nil
}

func (e *E2EApp) Stop(ctx context.Context) error {
	if e.TestServer != nil {
		e.TestServer.Close()
	}

	if e.App != nil {

		e.App.Stop()
	}

	if e.cleanup != nil {
		e.cleanup()
	}

	return nil
}

func BuildTestApp(builder *app.AppBuilder, testConfig *TestConfig) (*E2EApp, error) {

	cfg := createTestConfig(testConfig)
	builder = builder.WithConfig(cfg)

	var capturedDB *gorm.DB
	var capturedAuthSvc *auth.Service

	builder = builder.WithFxOptions(
		fx.Invoke(func(db *gorm.DB, authSvc *auth.Service) {
			capturedDB = db
			capturedAuthSvc = authSvc
		}),
	)

	builtApp, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build test app: %w", err)
	}

	e2eApp := &E2EApp{
		App:     builtApp,
		Config:  cfg,
		DB:      capturedDB,
		AuthSvc: capturedAuthSvc,
	}

	return e2eApp, nil
}
