package session

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/config"
)

func TestProvideSessionManager(t *testing.T) {
	t.Run("session disabled", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.SessionConfig{
				Enabled: false,
			},
		}
		logger := newTestLogger()

		manager, err := ProvideSessionManager(cfg, nil, nil, logger)

		require.NoError(t, err)
		assert.Nil(t, manager)
	})

	t.Run("memory store", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.SessionConfig{
				Enabled:  true,
				Store:    "memory",
				Name:     "test-session",
				MaxAge:   time.Hour,
				Secure:   false,
				HttpOnly: true,
				SameSite: "lax",
				Path:     "/",
				Domain:   "",
			},
		}
		logger := newTestLogger()

		manager, err := ProvideSessionManager(cfg, nil, nil, logger)

		require.NoError(t, err)
		require.NotNil(t, manager)
		assert.Equal(t, cfg.Session, manager.config)
		assert.NotNil(t, manager.SessionManager)
		assert.Equal(t, "test-session", manager.SessionManager.Cookie.Name)
		assert.Equal(t, time.Hour, manager.SessionManager.Lifetime)
		assert.False(t, manager.SessionManager.Cookie.Secure)
		assert.True(t, manager.SessionManager.Cookie.HttpOnly)
		assert.Equal(t, "/", manager.SessionManager.Cookie.Path)
	})

	t.Run("database store", func(t *testing.T) {
		db := setupTestDB(t)
		cfg := &config.Config{
			Session: config.SessionConfig{
				Enabled:  true,
				Store:    "database",
				Name:     "test-session",
				MaxAge:   time.Hour,
				Secure:   true,
				HttpOnly: true,
				SameSite: "strict",
				Path:     "/",
				Domain:   "example.com",
			},
		}
		logger := newTestLogger()

		manager, err := ProvideSessionManager(cfg, nil, db, logger)

		require.NoError(t, err)
		require.NotNil(t, manager)
		assert.Equal(t, cfg.Session, manager.config)
		assert.NotNil(t, manager.SessionManager)
		assert.True(t, manager.SessionManager.Cookie.Secure)
		assert.Equal(t, "example.com", manager.SessionManager.Cookie.Domain)
	})

	t.Run("database store without database", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.SessionConfig{
				Enabled: true,
				Store:   "database",
			},
		}

		manager, err := ProvideSessionManager(cfg, nil, nil, nil)

		assert.Error(t, err)
		assert.Nil(t, manager)
		assert.Contains(t, err.Error(), "database store requires database to be enabled")
	})

	t.Run("unsupported store", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.SessionConfig{
				Enabled: true,
				Store:   "unsupported",
			},
		}

		manager, err := ProvideSessionManager(cfg, nil, nil, nil)

		assert.Error(t, err)
		assert.Nil(t, manager)
		assert.Contains(t, err.Error(), "unsupported session store: unsupported")
	})

	t.Run("with custom store in options", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.SessionConfig{
				Enabled: true,
				Store:   "memory",
				Name:    "test-session",
				MaxAge:  time.Hour,
			},
		}
		mockStore := &MockStore{}
		opts := &Options{Store: mockStore}

		manager, err := ProvideSessionManager(cfg, opts, nil, nil)

		require.NoError(t, err)
		require.NotNil(t, manager)
		assert.Equal(t, mockStore, manager.SessionManager.Store)
	})

	t.Run("different SameSite values", func(t *testing.T) {
		testCases := []struct {
			name     string
			sameSite string
		}{
			{"strict", "strict"},
			{"lax", "lax"},
			{"none", "none"},
			{"default", "invalid"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cfg := &config.Config{
					Session: config.SessionConfig{
						Enabled:  true,
						Store:    "memory",
						SameSite: tc.sameSite,
					},
				}

				manager, err := ProvideSessionManager(cfg, nil, nil, nil)

				require.NoError(t, err)
				require.NotNil(t, manager)
			})
		}
	})

	t.Run("without logger", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.SessionConfig{
				Enabled: true,
				Store:   "memory",
			},
		}

		manager, err := ProvideSessionManager(cfg, nil, nil, nil)

		require.NoError(t, err)
		assert.NotNil(t, manager)
	})
}

func TestProvideSessionService(t *testing.T) {
	t.Run("with database and manager", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		logger := newTestLogger()

		service := ProvideSessionService(db, manager, logger)

		assert.NotNil(t, service)
	})

	t.Run("without database", func(t *testing.T) {
		manager := setupTestSessionManager()
		logger := newTestLogger()

		service := ProvideSessionService(nil, manager, logger)

		assert.Nil(t, service)
	})

	t.Run("without manager", func(t *testing.T) {
		db := setupTestDB(t)
		logger := newTestLogger()

		service := ProvideSessionService(db, nil, logger)

		assert.Nil(t, service)
	})

	t.Run("without logger", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()

		service := ProvideSessionService(db, manager, nil)

		assert.NotNil(t, service)
	})
}

func TestWireJWTRevocationService(t *testing.T) {
	t.Run("with JWT service", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		sessionSvc := NewSessionService(db, manager, nil)
		mockJWTSvc := &MockJWTRevocationService{}

		optJWTSvc := OptionalJWTService{JWTService: mockJWTSvc}

		WireJWTRevocationService(sessionSvc, optJWTSvc)

		svc := sessionSvc.(*sessionService)
		assert.Equal(t, mockJWTSvc, svc.jwtRevocation)
	})

	t.Run("without JWT service", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		sessionSvc := NewSessionService(db, manager, nil)

		optJWTSvc := OptionalJWTService{JWTService: nil}

		WireJWTRevocationService(sessionSvc, optJWTSvc)

		svc := sessionSvc.(*sessionService)
		assert.Nil(t, svc.jwtRevocation)
	})

	t.Run("with nil session service", func(t *testing.T) {
		mockJWTSvc := &MockJWTRevocationService{}
		optJWTSvc := OptionalJWTService{JWTService: mockJWTSvc}

		WireJWTRevocationService(nil, optJWTSvc)
	})
}

func TestWireRefreshTokenRevocationService(t *testing.T) {
	t.Run("with refresh token service", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		sessionSvc := NewSessionService(db, manager, nil)
		mockRefreshSvc := &MockRefreshTokenRevocationService{}

		optRefreshSvc := OptionalRefreshTokenService{RefreshTokenService: mockRefreshSvc}

		WireRefreshTokenRevocationService(sessionSvc, optRefreshSvc)

		svc := sessionSvc.(*sessionService)
		assert.Equal(t, mockRefreshSvc, svc.refreshRevocation)
	})

	t.Run("without refresh token service", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		sessionSvc := NewSessionService(db, manager, nil)

		optRefreshSvc := OptionalRefreshTokenService{RefreshTokenService: nil}

		WireRefreshTokenRevocationService(sessionSvc, optRefreshSvc)

		svc := sessionSvc.(*sessionService)
		assert.Nil(t, svc.refreshRevocation)
	})

	t.Run("with nil session service", func(t *testing.T) {
		mockRefreshSvc := &MockRefreshTokenRevocationService{}
		optRefreshSvc := OptionalRefreshTokenService{RefreshTokenService: mockRefreshSvc}

		WireRefreshTokenRevocationService(nil, optRefreshSvc)
	})
}
