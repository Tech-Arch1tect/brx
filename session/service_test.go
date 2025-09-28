package session

import (
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type MockJWTRevocationService struct {
	mock.Mock
}

func (m *MockJWTRevocationService) RevokeToken(jti string, expiresAt time.Time) error {
	args := m.Called(jti, expiresAt)
	return args.Error(0)
}

type MockRefreshTokenRevocationService struct {
	mock.Mock
}

func (m *MockRefreshTokenRevocationService) RevokeRefreshTokenByID(refreshTokenID uint) error {
	args := m.Called(refreshTokenID)
	return args.Error(0)
}

type MockStore struct {
	data map[string][]byte
}

func (m *MockStore) Find(token string) ([]byte, bool, error) {
	if data, exists := m.data[token]; exists {
		return data, true, nil
	}
	return nil, false, nil
}

func (m *MockStore) Commit(token string, b []byte, expiry time.Time) error {
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	m.data[token] = b
	return nil
}

func (m *MockStore) Delete(token string) error {
	if m.data != nil {
		delete(m.data, token)
	}
	return nil
}

func (m *MockStore) All() (map[string][]byte, error) {
	return m.data, nil
}

func newTestLogger() *logging.Service {
	config := logging.Config{
		Level:      logging.Debug,
		Format:     "console",
		OutputPath: "stdout",
	}
	logger, _ := logging.NewService(config)
	return logger
}

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&UserSession{})
	require.NoError(t, err)

	return db
}

func setupTestSessionManager() *Manager {
	store := &MockStore{}
	sessionManager := scs.New()
	sessionManager.Store = store

	return &Manager{
		SessionManager: sessionManager,
		config: config.SessionConfig{
			MaxAge: time.Hour,
		},
	}
}

func TestNewSessionService(t *testing.T) {
	t.Run("with logger", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		logger := newTestLogger()

		service := NewSessionService(db, manager, logger)

		require.NotNil(t, service)
		svc := service.(*sessionService)
		assert.Equal(t, db, svc.db)
		assert.Equal(t, manager, svc.sessionManager)
		assert.Equal(t, logger, svc.logger)
		assert.Nil(t, svc.jwtRevocation)
		assert.Nil(t, svc.refreshRevocation)
	})

	t.Run("without logger", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()

		service := NewSessionService(db, manager, nil)

		require.NotNil(t, service)
		svc := service.(*sessionService)
		assert.Equal(t, db, svc.db)
		assert.Equal(t, manager, svc.sessionManager)
		assert.Nil(t, svc.logger)
	})
}

func TestSessionService_SetJWTRevocationService(t *testing.T) {
	db := setupTestDB(t)
	manager := setupTestSessionManager()
	service := NewSessionService(db, manager, nil).(*sessionService)

	mockJWTService := &MockJWTRevocationService{}
	service.SetJWTRevocationService(mockJWTService)

	assert.Equal(t, mockJWTService, service.jwtRevocation)
}

func TestSessionService_SetRefreshTokenRevocationService(t *testing.T) {
	db := setupTestDB(t)
	manager := setupTestSessionManager()
	service := NewSessionService(db, manager, nil).(*sessionService)

	mockRefreshService := &MockRefreshTokenRevocationService{}
	service.SetRefreshTokenRevocationService(mockRefreshService)

	assert.Equal(t, mockRefreshService, service.refreshRevocation)
}

func TestSessionService_TrackSession(t *testing.T) {
	t.Run("successful tracking", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		logger := newTestLogger()
		service := NewSessionService(db, manager, logger)

		userID := uint(123)
		token := "test-token"
		sessionType := SessionTypeWeb
		ipAddress := "192.168.1.1"
		userAgent := "Test Browser"
		expiresAt := time.Now().Add(time.Hour)

		err := service.TrackSession(userID, token, sessionType, ipAddress, userAgent, expiresAt)

		require.NoError(t, err)

		var session UserSession
		err = db.Where("token = ?", token).First(&session).Error
		require.NoError(t, err)

		assert.Equal(t, userID, session.UserID)
		assert.Equal(t, token, session.Token)
		assert.Equal(t, sessionType, session.Type)
		assert.Equal(t, ipAddress, session.IPAddress)
		assert.Equal(t, userAgent, session.UserAgent)
		assert.WithinDuration(t, expiresAt, session.ExpiresAt, time.Second)
	})

	t.Run("without logger", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		err := service.TrackSession(1, "token", SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))

		assert.NoError(t, err)
	})
}

func TestSessionService_TrackJWTSessionWithRefreshToken(t *testing.T) {
	t.Run("successful JWT session tracking", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		logger := newTestLogger()
		service := NewSessionService(db, manager, logger)

		userID := uint(123)
		accessJTI := "access-jti-123"
		refreshTokenID := uint(456)
		ipAddress := "192.168.1.1"
		userAgent := "Test Browser"
		expiresAt := time.Now().Add(time.Hour)

		err := service.TrackJWTSessionWithRefreshToken(userID, accessJTI, refreshTokenID, ipAddress, userAgent, expiresAt)

		require.NoError(t, err)

		var session UserSession
		err = db.Where("refresh_token_id = ?", refreshTokenID).First(&session).Error
		require.NoError(t, err)

		assert.Equal(t, userID, session.UserID)
		assert.Equal(t, SessionTypeJWT, session.Type)
		assert.Equal(t, accessJTI, session.AccessTokenJTI)
		assert.Equal(t, refreshTokenID, session.RefreshTokenID)
		assert.Equal(t, ipAddress, session.IPAddress)
		assert.Equal(t, userAgent, session.UserAgent)
		assert.WithinDuration(t, expiresAt, session.ExpiresAt, time.Second)
		assert.NotEmpty(t, session.Token)
	})

	t.Run("without logger", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		err := service.TrackJWTSessionWithRefreshToken(1, "jti", 1, "127.0.0.1", "Browser", time.Now().Add(time.Hour))

		assert.NoError(t, err)
	})
}

func TestSessionService_GetJWTSessionByRefreshTokenID(t *testing.T) {
	t.Run("session found", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		logger := newTestLogger()
		service := NewSessionService(db, manager, logger)

		refreshTokenID := uint(456)

		err := service.TrackJWTSessionWithRefreshToken(123, "jti", refreshTokenID, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		session, err := service.GetJWTSessionByRefreshTokenID(refreshTokenID)

		require.NoError(t, err)
		assert.NotNil(t, session)
		assert.Equal(t, refreshTokenID, session.RefreshTokenID)
		assert.Equal(t, SessionTypeJWT, session.Type)
	})

	t.Run("session not found", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		logger := newTestLogger()
		service := NewSessionService(db, manager, logger)

		session, err := service.GetJWTSessionByRefreshTokenID(999)

		assert.Error(t, err)
		assert.Nil(t, session)
	})

	t.Run("without logger", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		session, err := service.GetJWTSessionByRefreshTokenID(999)

		assert.Error(t, err)
		assert.Nil(t, session)
	})
}

func TestSessionService_UpdateJWTSessionWithRefreshToken(t *testing.T) {
	t.Run("successful update", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		logger := newTestLogger()
		service := NewSessionService(db, manager, logger)

		oldRefreshTokenID := uint(456)
		newAccessJTI := "new-jti"
		newRefreshTokenID := uint(789)
		newExpiresAt := time.Now().Add(2 * time.Hour)

		err := service.TrackJWTSessionWithRefreshToken(123, "old-jti", oldRefreshTokenID, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		err = service.UpdateJWTSessionWithRefreshToken(oldRefreshTokenID, newAccessJTI, newRefreshTokenID, newExpiresAt)

		require.NoError(t, err)

		var session UserSession
		err = db.Where("refresh_token_id = ?", newRefreshTokenID).First(&session).Error
		require.NoError(t, err)

		assert.Equal(t, newAccessJTI, session.AccessTokenJTI)
		assert.Equal(t, newRefreshTokenID, session.RefreshTokenID)
		assert.WithinDuration(t, newExpiresAt, session.ExpiresAt, time.Second)
	})

	t.Run("session not found", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		err := service.UpdateJWTSessionWithRefreshToken(999, "jti", 888, time.Now())

		assert.NoError(t, err)
	})
}

func TestSessionService_generateSessionTokenFromID(t *testing.T) {
	db := setupTestDB(t)
	manager := setupTestSessionManager()
	service := NewSessionService(db, manager, nil).(*sessionService)

	token1 := service.generateSessionTokenFromID(123)
	token2 := service.generateSessionTokenFromID(123)
	token3 := service.generateSessionTokenFromID(456)

	assert.Equal(t, token1, token2)
	assert.NotEqual(t, token1, token3)
	assert.NotEmpty(t, token1)
	assert.Len(t, token1, 64)
}

func TestSessionService_UpdateLastUsed(t *testing.T) {
	t.Run("successful update", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		token := "test-token"
		err := service.TrackSession(123, token, SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		err = service.UpdateLastUsed(token)

		require.NoError(t, err)

		var session UserSession
		err = db.Where("token = ?", token).First(&session).Error
		require.NoError(t, err)
		assert.True(t, session.LastUsed.After(session.CreatedAt))
	})

	t.Run("token not found", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		err := service.UpdateLastUsed("nonexistent-token")

		assert.NoError(t, err)
	})
}

func TestSessionService_GetUserSessions(t *testing.T) {
	t.Run("multiple sessions found", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		logger := newTestLogger()
		service := NewSessionService(db, manager, logger)

		userID := uint(123)
		currentToken := "current-token"

		err := service.TrackSession(userID, currentToken, SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		err = service.TrackSession(userID, "other-token", SessionTypeWeb, "192.168.1.1", "Other Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		sessions, err := service.GetUserSessions(userID, currentToken)

		require.NoError(t, err)
		assert.Len(t, sessions, 2)

		var currentSessionFound bool
		for _, session := range sessions {
			if session.Token == currentToken {
				assert.True(t, session.Current)
				currentSessionFound = true
			} else {
				assert.False(t, session.Current)
			}
		}
		assert.True(t, currentSessionFound)
	})

	t.Run("no sessions found", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		sessions, err := service.GetUserSessions(999, "token")

		require.NoError(t, err)
		assert.Empty(t, sessions)
	})

	t.Run("expired sessions excluded", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		userID := uint(123)

		err := service.TrackSession(userID, "valid-token", SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		err = service.TrackSession(userID, "expired-token", SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(-time.Hour))
		require.NoError(t, err)

		sessions, err := service.GetUserSessions(userID, "valid-token")

		require.NoError(t, err)
		assert.Len(t, sessions, 1)
		assert.Equal(t, "valid-token", sessions[0].Token)
	})
}

func TestGetBrowserInfo(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		expected  string
	}{
		{
			name:      "empty user agent",
			userAgent: "",
			expected:  "Unknown Browser",
		},
		{
			name:      "chrome user agent",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			expected:  "Chrome",
		},
		{
			name:      "firefox user agent",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
			expected:  "Firefox",
		},
		{
			name:      "safari user agent",
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
			expected:  "Safari",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetBrowserInfo(tt.userAgent)
			if tt.name == "chrome user agent" || tt.name == "firefox user agent" || tt.name == "safari user agent" {
				assert.Contains(t, result, tt.expected)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGetDeviceInfo(t *testing.T) {
	t.Run("empty user agent", func(t *testing.T) {
		info := GetDeviceInfo("")

		assert.Equal(t, "Unknown Browser", info["browser"])
		assert.Equal(t, "", info["browser_version"])
		assert.Equal(t, "Unknown OS", info["os"])
		assert.Equal(t, "", info["os_version"])
		assert.Equal(t, "Unknown", info["device_type"])
		assert.Equal(t, "Unknown Device", info["device"])
		assert.False(t, info["mobile"].(bool))
		assert.False(t, info["tablet"].(bool))
		assert.False(t, info["desktop"].(bool))
		assert.False(t, info["bot"].(bool))
	})

	t.Run("desktop chrome user agent", func(t *testing.T) {
		userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
		info := GetDeviceInfo(userAgent)

		assert.Contains(t, info["browser"].(string), "Chrome")
		assert.Equal(t, "Desktop", info["device_type"])
		assert.False(t, info["mobile"].(bool))
		assert.False(t, info["tablet"].(bool))
		assert.True(t, info["desktop"].(bool))
		assert.False(t, info["bot"].(bool))
	})
}

func TestGetLocationInfo(t *testing.T) {
	tests := []struct {
		name      string
		ipAddress string
		expected  string
	}{
		{
			name:      "empty IP",
			ipAddress: "",
			expected:  "Local",
		},
		{
			name:      "localhost IPv4",
			ipAddress: "127.0.0.1",
			expected:  "Local",
		},
		{
			name:      "localhost IPv6",
			ipAddress: "::1",
			expected:  "Local",
		},
		{
			name:      "public IP",
			ipAddress: "8.8.8.8",
			expected:  "Unknown Location",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetLocationInfo(tt.ipAddress)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSessionService_RevokeSession(t *testing.T) {
	t.Run("revoke web session", func(t *testing.T) {
		db := setupTestDB(t)
		mockStore := &MockStore{}
		manager := setupTestSessionManager()
		manager.SessionManager = &scs.SessionManager{Store: mockStore}
		logger := newTestLogger()
		service := NewSessionService(db, manager, logger)

		userID := uint(123)
		token := "test-token"

		err := service.TrackSession(userID, token, SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		var session UserSession
		err = db.Where("token = ?", token).First(&session).Error
		require.NoError(t, err)

		err = service.RevokeSession(userID, session.ID)

		require.NoError(t, err)

		var count int64
		db.Model(&UserSession{}).Where("id = ?", session.ID).Count(&count)
		assert.Equal(t, int64(0), count)
	})

	t.Run("revoke JWT session with revocation services", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		logger := newTestLogger()
		service := NewSessionService(db, manager, logger).(*sessionService)

		mockJWTService := &MockJWTRevocationService{}
		mockRefreshService := &MockRefreshTokenRevocationService{}

		service.SetJWTRevocationService(mockJWTService)
		service.SetRefreshTokenRevocationService(mockRefreshService)

		userID := uint(123)
		accessJTI := "access-jti"
		refreshTokenID := uint(456)

		mockJWTService.On("RevokeToken", accessJTI, mock.AnythingOfType("time.Time")).Return(nil)
		mockRefreshService.On("RevokeRefreshTokenByID", refreshTokenID).Return(nil)

		err := service.TrackJWTSessionWithRefreshToken(userID, accessJTI, refreshTokenID, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		var session UserSession
		err = db.Where("refresh_token_id = ?", refreshTokenID).First(&session).Error
		require.NoError(t, err)

		err = service.RevokeSession(userID, session.ID)

		require.NoError(t, err)
		mockJWTService.AssertExpectations(t)
		mockRefreshService.AssertExpectations(t)

		var count int64
		db.Model(&UserSession{}).Where("id = ?", session.ID).Count(&count)
		assert.Equal(t, int64(0), count)
	})

	t.Run("session not found", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		err := service.RevokeSession(123, 999)

		assert.Error(t, err)
	})

	t.Run("session belongs to different user", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		userID := uint(123)
		token := "test-token"

		err := service.TrackSession(userID, token, SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		var session UserSession
		err = db.Where("token = ?", token).First(&session).Error
		require.NoError(t, err)

		err = service.RevokeSession(456, session.ID)

		assert.Error(t, err)
	})
}

func TestSessionService_RevokeAllOtherSessions(t *testing.T) {
	t.Run("revoke multiple sessions", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		logger := newTestLogger()
		service := NewSessionService(db, manager, logger)

		userID := uint(123)
		currentToken := "current-token"

		err := service.TrackSession(userID, currentToken, SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		err = service.TrackSession(userID, "other-token-1", SessionTypeWeb, "192.168.1.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		err = service.TrackSession(userID, "other-token-2", SessionTypeWeb, "10.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		err = service.RevokeAllOtherSessions(userID, currentToken)

		require.NoError(t, err)

		var sessions []UserSession
		db.Where("user_id = ?", userID).Find(&sessions)

		assert.Len(t, sessions, 1)
		assert.Equal(t, currentToken, sessions[0].Token)
	})

	t.Run("no other sessions to revoke", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		logger := newTestLogger()
		service := NewSessionService(db, manager, logger)

		userID := uint(123)
		currentToken := "current-token"

		err := service.TrackSession(userID, currentToken, SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		err = service.RevokeAllOtherSessions(userID, currentToken)

		require.NoError(t, err)

		var count int64
		db.Model(&UserSession{}).Where("user_id = ?", userID).Count(&count)
		assert.Equal(t, int64(1), count)
	})

	t.Run("with JWT sessions and revocation services", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil).(*sessionService)

		mockJWTService := &MockJWTRevocationService{}
		mockRefreshService := &MockRefreshTokenRevocationService{}

		service.SetJWTRevocationService(mockJWTService)
		service.SetRefreshTokenRevocationService(mockRefreshService)

		userID := uint(123)
		currentToken := "current-token"

		mockJWTService.On("RevokeToken", "jti-1", mock.AnythingOfType("time.Time")).Return(nil)
		mockRefreshService.On("RevokeRefreshTokenByID", uint(456)).Return(nil)

		err := service.TrackSession(userID, currentToken, SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		err = service.TrackJWTSessionWithRefreshToken(userID, "jti-1", 456, "192.168.1.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		err = service.RevokeAllOtherSessions(userID, currentToken)

		require.NoError(t, err)
		mockJWTService.AssertExpectations(t)
		mockRefreshService.AssertExpectations(t)
	})
}

func TestSessionService_CleanupExpiredSessions(t *testing.T) {
	t.Run("cleanup expired sessions", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		logger := newTestLogger()
		service := NewSessionService(db, manager, logger)

		err := service.TrackSession(123, "valid-token", SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		err = service.TrackSession(123, "expired-token", SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(-time.Hour))
		require.NoError(t, err)

		err = service.CleanupExpiredSessions()

		require.NoError(t, err)

		var count int64
		db.Model(&UserSession{}).Count(&count)
		assert.Equal(t, int64(1), count)

		var validSession UserSession
		err = db.Where("token = ?", "valid-token").First(&validSession).Error
		assert.NoError(t, err)
	})

	t.Run("no expired sessions", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		err := service.TrackSession(123, "valid-token", SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		err = service.CleanupExpiredSessions()

		require.NoError(t, err)

		var count int64
		db.Model(&UserSession{}).Count(&count)
		assert.Equal(t, int64(1), count)
	})
}

func TestSessionService_SessionExists(t *testing.T) {
	t.Run("session exists and valid", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		token := "test-token"
		err := service.TrackSession(123, token, SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		exists, err := service.SessionExists(token)

		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("session expired", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		token := "expired-token"
		err := service.TrackSession(123, token, SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(-time.Hour))
		require.NoError(t, err)

		exists, err := service.SessionExists(token)

		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("session not found", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		exists, err := service.SessionExists("nonexistent-token")

		require.NoError(t, err)
		assert.False(t, exists)
	})
}

func TestSessionService_RemoveSessionByToken(t *testing.T) {
	t.Run("successful removal", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		logger := newTestLogger()
		service := NewSessionService(db, manager, logger)

		token := "test-token"
		err := service.TrackSession(123, token, SessionTypeWeb, "127.0.0.1", "Browser", time.Now().Add(time.Hour))
		require.NoError(t, err)

		err = service.RemoveSessionByToken(token)

		require.NoError(t, err)

		var count int64
		db.Model(&UserSession{}).Where("token = ?", token).Count(&count)
		assert.Equal(t, int64(0), count)
	})

	t.Run("token not found", func(t *testing.T) {
		db := setupTestDB(t)
		manager := setupTestSessionManager()
		service := NewSessionService(db, manager, nil)

		err := service.RemoveSessionByToken("nonexistent-token")

		assert.NoError(t, err)
	})
}
