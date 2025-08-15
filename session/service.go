package session

import (
	"time"

	"github.com/mileusna/useragent"
	"gorm.io/gorm"
)

type sessionService struct {
	db             *gorm.DB
	sessionManager *Manager
}

func NewSessionService(db *gorm.DB, sessionManager *Manager) SessionService {
	return &sessionService{
		db:             db,
		sessionManager: sessionManager,
	}
}

func (s *sessionService) TrackSession(userID uint, token string, ipAddress, userAgent string, expiresAt time.Time) error {
	session := UserSession{
		UserID:    userID,
		Token:     token,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		ExpiresAt: expiresAt,
	}

	return s.db.Create(&session).Error
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

	if s.sessionManager != nil && s.sessionManager.SessionManager.Store != nil {
		err = s.sessionManager.SessionManager.Store.Delete(session.Token)
		if err != nil {
			return err
		}
	}

	return s.db.Delete(&session).Error
}

func (s *sessionService) RevokeAllOtherSessions(userID uint, currentToken string) error {

	var tokens []string
	err := s.db.Model(&UserSession{}).
		Where("user_id = ? AND token != ?", userID, currentToken).
		Pluck("token", &tokens).Error
	if err != nil {
		return err
	}

	if len(tokens) == 0 {
		return nil
	}

	if s.sessionManager != nil && s.sessionManager.SessionManager.Store != nil {
		for _, token := range tokens {
			err = s.sessionManager.SessionManager.Store.Delete(token)
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
