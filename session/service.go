package session

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/mileusna/useragent"
	"gorm.io/gorm"
)

type JWTRevocationService interface {
	RevokeToken(tokenString string) error
}

type sessionService struct {
	db             *gorm.DB
	sessionManager *Manager
	jwtRevocation  JWTRevocationService
}

func NewSessionService(db *gorm.DB, sessionManager *Manager) SessionService {
	return &sessionService{
		db:             db,
		sessionManager: sessionManager,
		jwtRevocation:  nil,
	}
}

func (s *sessionService) SetJWTRevocationService(jwtRevocation JWTRevocationService) {
	s.jwtRevocation = jwtRevocation
}

func (s *sessionService) TrackSession(userID uint, token string, sessionType SessionType, ipAddress, userAgent string, expiresAt time.Time) error {
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

	return s.db.Create(&session).Error
}

func (s *sessionService) TrackJWTSession(userID uint, accessToken, refreshToken string, ipAddress, userAgent string, expiresAt time.Time) error {
	sessionToken := s.generateSessionToken(refreshToken)

	session := UserSession{
		UserID:       userID,
		Token:        sessionToken,
		Type:         SessionTypeJWT,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		ExpiresAt:    expiresAt,
	}

	return s.db.Create(&session).Error
}

func (s *sessionService) GetJWTSessionByRefreshToken(refreshToken string) (*UserSession, error) {
	sessionToken := s.generateSessionToken(refreshToken)

	var session UserSession
	err := s.db.Where("token = ? AND type = ?", sessionToken, SessionTypeJWT).First(&session).Error
	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (s *sessionService) UpdateJWTSession(oldRefreshToken, newAccessToken, newRefreshToken string, expiresAt time.Time) error {
	oldSessionToken := s.generateSessionToken(oldRefreshToken)
	newSessionToken := s.generateSessionToken(newRefreshToken)

	return s.db.Model(&UserSession{}).
		Where("token = ? AND type = ?", oldSessionToken, SessionTypeJWT).
		Updates(map[string]any{
			"token":         newSessionToken,
			"access_token":  newAccessToken,
			"refresh_token": newRefreshToken,
			"expires_at":    expiresAt,
			"last_used":     time.Now(),
		}).Error
}

func (s *sessionService) generateSessionToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *sessionService) UpdateLastUsed(token string) error {
	return s.db.Model(&UserSession{}).
		Where("token = ?", token).
		Update("last_used", time.Now()).Error
}

func (s *sessionService) GetUserSessions(userID uint, currentToken string) ([]UserSession, error) {
	var sessions []UserSession

	err := s.db.Where("user_id = ? AND expires_at > ?", userID, time.Now()).
		Order("last_used DESC").
		Find(&sessions).Error

	if err != nil {
		return nil, err
	}

	for i := range sessions {
		if sessions[i].Token == currentToken {
			sessions[i].Current = true
		}
	}

	return sessions, nil
}

func (s *sessionService) RevokeSession(userID uint, sessionID uint) error {

	var session UserSession
	err := s.db.Where("id = ? AND user_id = ?", sessionID, userID).First(&session).Error
	if err != nil {
		return err
	}

	if session.Type == SessionTypeJWT && s.jwtRevocation != nil {

		if session.AccessToken != "" {
			_ = s.jwtRevocation.RevokeToken(session.AccessToken)
		}
		if session.RefreshToken != "" {
			_ = s.jwtRevocation.RevokeToken(session.RefreshToken)
		}
	}

	if session.Type == SessionTypeWeb && s.sessionManager != nil && s.sessionManager.SessionManager.Store != nil {
		err = s.sessionManager.SessionManager.Store.Delete(session.Token)
		if err != nil {
			return err
		}
	}

	return s.db.Delete(&session).Error
}

func (s *sessionService) RevokeAllOtherSessions(userID uint, currentToken string) error {

	var sessions []UserSession
	err := s.db.Where("user_id = ? AND token != ?", userID, currentToken).Find(&sessions).Error
	if err != nil {
		return err
	}

	if len(sessions) == 0 {
		return nil
	}

	for _, session := range sessions {
		if session.Type == SessionTypeJWT && s.jwtRevocation != nil {
			if session.AccessToken != "" {
				_ = s.jwtRevocation.RevokeToken(session.AccessToken)
			}
			if session.RefreshToken != "" {
				_ = s.jwtRevocation.RevokeToken(session.RefreshToken)
			}
		}

		if session.Type == SessionTypeWeb && s.sessionManager != nil && s.sessionManager.SessionManager.Store != nil {
			err = s.sessionManager.SessionManager.Store.Delete(session.Token)
			if err != nil {
				return err
			}
		}
	}

	return s.db.Where("user_id = ? AND token != ?", userID, currentToken).Delete(&UserSession{}).Error
}

func (s *sessionService) CleanupExpiredSessions() error {

	return s.db.Where("expires_at < ?", time.Now()).Delete(&UserSession{}).Error
}

func (s *sessionService) SessionExists(token string) (bool, error) {
	var count int64
	err := s.db.Model(&UserSession{}).
		Where("token = ? AND expires_at > ?", token, time.Now()).
		Count(&count).Error

	if err != nil {
		return false, err
	}

	if count > 0 {
		_ = s.UpdateLastUsed(token)
		return true, nil
	}

	return false, nil
}

func (s *sessionService) RemoveSessionByToken(token string) error {
	return s.db.Where("token = ?", token).Delete(&UserSession{}).Error
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
