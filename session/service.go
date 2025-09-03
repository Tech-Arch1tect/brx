package session

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/mileusna/useragent"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type JWTRevocationService interface {
	RevokeToken(jti string, expiresAt time.Time) error
}

type RefreshTokenRevocationService interface {
	RevokeRefreshTokenByID(refreshTokenID uint) error
}

type sessionService struct {
	db                *gorm.DB
	sessionManager    *Manager
	jwtRevocation     JWTRevocationService
	refreshRevocation RefreshTokenRevocationService
	logger            *logging.Service
}

func NewSessionService(db *gorm.DB, sessionManager *Manager, logger *logging.Service) SessionService {
	if logger != nil {
		logger.Info("initializing session service")
	}

	return &sessionService{
		db:                db,
		sessionManager:    sessionManager,
		jwtRevocation:     nil,
		refreshRevocation: nil,
		logger:            logger,
	}
}

func (s *sessionService) SetJWTRevocationService(jwtRevocation JWTRevocationService) {
	s.jwtRevocation = jwtRevocation
}

func (s *sessionService) SetRefreshTokenRevocationService(refreshRevocation RefreshTokenRevocationService) {
	s.refreshRevocation = refreshRevocation
}

func (s *sessionService) TrackSession(userID uint, token string, sessionType SessionType, ipAddress, userAgent string, expiresAt time.Time) error {
	if s.logger != nil {
		s.logger.Info("tracking new session",
			zap.Uint("user_id", userID),
			zap.String("session_type", string(sessionType)),
			zap.String("ip_address", ipAddress),
			zap.String("browser", GetBrowserInfo(userAgent)),
			zap.Time("expires_at", expiresAt))
	}

	session := UserSession{
		UserID:    userID,
		Token:     token,
		Type:      sessionType,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		ExpiresAt: expiresAt,
	}

	err := s.db.Create(&session).Error
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to track session",
				zap.Error(err),
				zap.Uint("user_id", userID),
				zap.String("session_type", string(sessionType)))
		}
		return err
	}

	if s.logger != nil {
		s.logger.Debug("session tracked successfully",
			zap.Uint("user_id", userID),
			zap.Uint("session_id", session.ID))
	}

	return nil
}

func (s *sessionService) TrackJWTSessionWithRefreshToken(userID uint, accessJTI string, refreshTokenID uint, ipAddress, userAgent string, expiresAt time.Time) error {
	if s.logger != nil {
		s.logger.Info("tracking JWT session with refresh token",
			zap.Uint("user_id", userID),
			zap.String("access_jti", accessJTI),
			zap.Uint("refresh_token_id", refreshTokenID),
			zap.String("ip_address", ipAddress),
			zap.String("browser", GetBrowserInfo(userAgent)),
			zap.Time("expires_at", expiresAt))
	}

	sessionToken := s.generateSessionTokenFromID(refreshTokenID)
	session := UserSession{
		UserID:         userID,
		Token:          sessionToken,
		Type:           SessionTypeJWT,
		AccessTokenJTI: accessJTI,
		RefreshTokenID: refreshTokenID,
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		CreatedAt:      time.Now(),
		LastUsed:       time.Now(),
		ExpiresAt:      expiresAt,
	}

	err := s.db.Create(&session).Error
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to track JWT session",
				zap.Error(err),
				zap.Uint("user_id", userID),
				zap.String("access_jti", accessJTI),
				zap.Uint("refresh_token_id", refreshTokenID))
		}
		return err
	}

	if s.logger != nil {
		s.logger.Debug("JWT session tracked successfully",
			zap.Uint("user_id", userID),
			zap.Uint("session_id", session.ID),
			zap.String("access_jti", accessJTI))
	}

	return nil
}

func (s *sessionService) GetJWTSessionByRefreshTokenID(refreshTokenID uint) (*UserSession, error) {
	if s.logger != nil {
		s.logger.Debug("retrieving JWT session by refresh token ID",
			zap.Uint("refresh_token_id", refreshTokenID))
	}

	var session UserSession
	err := s.db.Where("refresh_token_id = ? AND type = ?", refreshTokenID, SessionTypeJWT).First(&session).Error
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("JWT session not found by refresh token ID",
				zap.Error(err),
				zap.Uint("refresh_token_id", refreshTokenID))
		}
		return nil, err
	}

	if s.logger != nil {
		s.logger.Debug("JWT session retrieved successfully",
			zap.Uint("refresh_token_id", refreshTokenID),
			zap.Uint("session_id", session.ID),
			zap.Uint("user_id", session.UserID))
	}

	return &session, nil
}

func (s *sessionService) UpdateJWTSessionWithRefreshToken(oldRefreshTokenID uint, newAccessJTI string, newRefreshTokenID uint, expiresAt time.Time) error {
	if s.logger != nil {
		s.logger.Info("updating JWT session with new refresh token",
			zap.Uint("old_refresh_token_id", oldRefreshTokenID),
			zap.String("new_access_jti", newAccessJTI),
			zap.Uint("new_refresh_token_id", newRefreshTokenID),
			zap.Time("new_expires_at", expiresAt))
	}

	newSessionToken := s.generateSessionTokenFromID(newRefreshTokenID)
	err := s.db.Model(&UserSession{}).
		Where("refresh_token_id = ? AND type = ?", oldRefreshTokenID, SessionTypeJWT).
		Updates(map[string]any{
			"token":            newSessionToken,
			"access_token_jti": newAccessJTI,
			"refresh_token_id": newRefreshTokenID,
			"expires_at":       expiresAt,
			"last_used":        time.Now(),
		}).Error

	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to update JWT session",
				zap.Error(err),
				zap.Uint("old_refresh_token_id", oldRefreshTokenID),
				zap.Uint("new_refresh_token_id", newRefreshTokenID))
		}
		return err
	}

	if s.logger != nil {
		s.logger.Debug("JWT session updated successfully",
			zap.Uint("old_refresh_token_id", oldRefreshTokenID),
			zap.Uint("new_refresh_token_id", newRefreshTokenID))
	}

	return nil
}

func (s *sessionService) generateSessionTokenFromID(refreshTokenID uint) string {
	hash := sha256.Sum256(fmt.Appendf(nil, "refresh_token_id_%d", refreshTokenID))
	return hex.EncodeToString(hash[:])
}

func (s *sessionService) UpdateLastUsed(token string) error {
	err := s.db.Model(&UserSession{}).
		Where("token = ?", token).
		Update("last_used", time.Now()).Error

	if err != nil && s.logger != nil {
		s.logger.Warn("failed to update session last used time",
			zap.Error(err))
	}

	return err
}

func (s *sessionService) GetUserSessions(userID uint, currentToken string) ([]UserSession, error) {
	if s.logger != nil {
		s.logger.Debug("retrieving active sessions for user",
			zap.Uint("user_id", userID))
	}

	var sessions []UserSession

	err := s.db.Where("user_id = ? AND expires_at > ?", userID, time.Now()).
		Order("last_used DESC").
		Find(&sessions).Error

	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to retrieve user sessions",
				zap.Error(err),
				zap.Uint("user_id", userID))
		}
		return nil, err
	}

	for i := range sessions {
		if sessions[i].Token == currentToken {
			sessions[i].Current = true
		}
	}

	if s.logger != nil {
		s.logger.Debug("user sessions retrieved successfully",
			zap.Uint("user_id", userID),
			zap.Int("session_count", len(sessions)))
	}

	return sessions, nil
}

func (s *sessionService) RevokeSession(userID uint, sessionID uint) error {
	if s.logger != nil {
		s.logger.Info("revoking session",
			zap.Uint("user_id", userID),
			zap.Uint("session_id", sessionID))
	}

	var session UserSession
	err := s.db.Where("id = ? AND user_id = ?", sessionID, userID).First(&session).Error
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("session not found for revocation",
				zap.Error(err),
				zap.Uint("user_id", userID),
				zap.Uint("session_id", sessionID))
		}
		return err
	}

	if session.Type == SessionTypeJWT && s.jwtRevocation != nil {
		if session.AccessTokenJTI != "" {
			if s.logger != nil {
				s.logger.Debug("revoking JWT access token",
					zap.String("access_jti", session.AccessTokenJTI))
			}
			_ = s.jwtRevocation.RevokeToken(session.AccessTokenJTI, session.ExpiresAt)
		}
	}

	if session.Type == SessionTypeJWT && s.refreshRevocation != nil && session.RefreshTokenID != 0 {
		if s.logger != nil {
			s.logger.Debug("revoking refresh token",
				zap.Uint("refresh_token_id", session.RefreshTokenID))
		}
		_ = s.refreshRevocation.RevokeRefreshTokenByID(session.RefreshTokenID)
	}

	if session.Type == SessionTypeWeb && s.sessionManager != nil && s.sessionManager.SessionManager.Store != nil {
		if s.logger != nil {
			s.logger.Debug("deleting web session from store")
		}
		err = s.sessionManager.SessionManager.Store.Delete(session.Token)
		if err != nil {
			if s.logger != nil {
				s.logger.Error("failed to delete session from store",
					zap.Error(err))
			}
			return err
		}
	}

	err = s.db.Delete(&session).Error
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to delete session from database",
				zap.Error(err),
				zap.Uint("session_id", sessionID))
		}
		return err
	}

	if s.logger != nil {
		s.logger.Info("session revoked successfully",
			zap.Uint("user_id", userID),
			zap.Uint("session_id", sessionID),
			zap.String("session_type", string(session.Type)))
	}

	return nil
}

func (s *sessionService) RevokeAllOtherSessions(userID uint, currentToken string) error {
	if s.logger != nil {
		s.logger.Info("revoking all other sessions for user",
			zap.Uint("user_id", userID))
	}

	var sessions []UserSession
	err := s.db.Where("user_id = ? AND token != ?", userID, currentToken).Find(&sessions).Error
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to find sessions to revoke",
				zap.Error(err),
				zap.Uint("user_id", userID))
		}
		return err
	}

	if len(sessions) == 0 {
		if s.logger != nil {
			s.logger.Debug("no other sessions to revoke",
				zap.Uint("user_id", userID))
		}
		return nil
	}

	if s.logger != nil {
		s.logger.Info("found sessions to revoke",
			zap.Uint("user_id", userID),
			zap.Int("session_count", len(sessions)))
	}

	for _, session := range sessions {
		if session.Type == SessionTypeJWT && s.jwtRevocation != nil {
			if session.AccessTokenJTI != "" {
				if s.logger != nil {
					s.logger.Debug("revoking JWT access token",
						zap.String("access_jti", session.AccessTokenJTI))
				}
				_ = s.jwtRevocation.RevokeToken(session.AccessTokenJTI, session.ExpiresAt)
			}
		}

		if session.Type == SessionTypeJWT && s.refreshRevocation != nil && session.RefreshTokenID != 0 {
			if s.logger != nil {
				s.logger.Debug("revoking refresh token",
					zap.Uint("refresh_token_id", session.RefreshTokenID))
			}
			_ = s.refreshRevocation.RevokeRefreshTokenByID(session.RefreshTokenID)
		}

		if session.Type == SessionTypeWeb && s.sessionManager != nil && s.sessionManager.SessionManager.Store != nil {
			if s.logger != nil {
				s.logger.Debug("deleting web session from store",
					zap.Uint("session_id", session.ID))
			}
			err = s.sessionManager.SessionManager.Store.Delete(session.Token)
			if err != nil {
				if s.logger != nil {
					s.logger.Error("failed to delete session from store",
						zap.Error(err),
						zap.Uint("session_id", session.ID))
				}
				return err
			}
		}
	}

	err = s.db.Where("user_id = ? AND token != ?", userID, currentToken).Delete(&UserSession{}).Error
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to delete sessions from database",
				zap.Error(err),
				zap.Uint("user_id", userID))
		}
		return err
	}

	if s.logger != nil {
		s.logger.Info("all other sessions revoked successfully",
			zap.Uint("user_id", userID),
			zap.Int("revoked_count", len(sessions)))
	}

	return nil
}

func (s *sessionService) CleanupExpiredSessions() error {
	if s.logger != nil {
		s.logger.Info("starting expired sessions cleanup")
	}

	result := s.db.Where("expires_at < ?", time.Now()).Delete(&UserSession{})
	if result.Error != nil {
		if s.logger != nil {
			s.logger.Error("failed to cleanup expired sessions",
				zap.Error(result.Error))
		}
		return result.Error
	}

	if s.logger != nil {
		s.logger.Info("expired sessions cleanup completed",
			zap.Int64("cleaned_count", result.RowsAffected))
	}

	return nil
}

func (s *sessionService) SessionExists(token string) (bool, error) {
	var count int64
	err := s.db.Model(&UserSession{}).
		Where("token = ? AND expires_at > ?", token, time.Now()).
		Count(&count).Error

	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to check session existence",
				zap.Error(err))
		}
		return false, err
	}

	if count > 0 {
		if s.logger != nil {
			s.logger.Debug("session exists and is valid")
		}
		_ = s.UpdateLastUsed(token)
		return true, nil
	}

	if s.logger != nil {
		s.logger.Debug("session not found or expired")
	}
	return false, nil
}

func (s *sessionService) RemoveSessionByToken(token string) error {
	if s.logger != nil {
		s.logger.Debug("removing session by token")
	}

	result := s.db.Where("token = ?", token).Delete(&UserSession{})
	if result.Error != nil {
		if s.logger != nil {
			s.logger.Error("failed to remove session by token",
				zap.Error(result.Error))
		}
		return result.Error
	}

	if s.logger != nil {
		s.logger.Debug("session removed successfully",
			zap.Int64("affected_rows", result.RowsAffected))
	}

	return nil
}

func GetBrowserInfo(userAgentString string) string {
	if userAgentString == "" {
		return "Unknown Browser"
	}

	ua := useragent.Parse(userAgentString)

	if ua.Name != "" {
		if ua.Version != "" {
			return ua.Name + " " + ua.Version
		}
		return ua.Name
	}

	return "Unknown Browser"
}

func GetDeviceInfo(userAgentString string) map[string]any {
	if userAgentString == "" {
		return map[string]any{
			"browser":         "Unknown Browser",
			"browser_version": "",
			"os":              "Unknown OS",
			"os_version":      "",
			"device_type":     "Unknown",
			"device":          "Unknown Device",
			"mobile":          false,
			"tablet":          false,
			"desktop":         false,
			"bot":             false,
		}
	}

	ua := useragent.Parse(userAgentString)

	deviceType := "Desktop"
	if ua.Mobile {
		deviceType = "Mobile"
	} else if ua.Tablet {
		deviceType = "Tablet"
	} else if ua.Bot {
		deviceType = "Bot"
	}

	browser := "Unknown Browser"
	if ua.Name != "" {
		if ua.Version != "" {
			browser = ua.Name + " " + ua.Version
		} else {
			browser = ua.Name
		}
	}

	os := "Unknown OS"
	if ua.OS != "" {
		if ua.OSVersion != "" {
			os = ua.OS + " " + ua.OSVersion
		} else {
			os = ua.OS
		}
	}

	device := "Unknown Device"
	if ua.Device != "" {
		device = ua.Device
	} else if ua.Mobile {
		device = "Mobile Device"
	} else if ua.Tablet {
		device = "Tablet"
	} else {
		device = "Desktop Computer"
	}

	return map[string]any{
		"browser":         browser,
		"browser_version": ua.Version,
		"os":              os,
		"os_version":      ua.OSVersion,
		"device_type":     deviceType,
		"device":          device,
		"mobile":          ua.Mobile,
		"tablet":          ua.Tablet,
		"desktop":         !ua.Mobile && !ua.Tablet && !ua.Bot,
		"bot":             ua.Bot,
	}
}

func GetLocationInfo(ipAddress string) string {
	if ipAddress == "" || ipAddress == "127.0.0.1" || ipAddress == "::1" {
		return "Local"
	}

	return "Unknown Location"
}
