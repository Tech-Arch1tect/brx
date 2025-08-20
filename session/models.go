package session

import (
	"time"
)

type SessionType string

const (
	SessionTypeWeb SessionType = "web"
	SessionTypeJWT SessionType = "jwt"
)

type UserSession struct {
	ID              uint        `json:"id" gorm:"primaryKey"`
	UserID          uint        `json:"user_id" gorm:"not null;index"`
	Token           string      `json:"token" gorm:"uniqueIndex;size:255;not null"`
	Type            SessionType `json:"type" gorm:"size:10;not null;default:'web'"`
	AccessTokenJTI  string      `json:"-" gorm:"size:50;index"` // JTI for access token
	RefreshTokenJTI string      `json:"-" gorm:"size:50;index"` // JTI for refresh token
	IPAddress       string      `json:"ip_address" gorm:"size:45"`
	UserAgent       string      `json:"user_agent" gorm:"size:500"`
	Current         bool        `json:"current" gorm:"-"`
	CreatedAt       time.Time   `json:"created_at"`
	LastUsed        time.Time   `json:"last_used"`
	ExpiresAt       time.Time   `json:"expires_at"`
}

func (UserSession) TableName() string {
	return "user_sessions"
}

// SessionService provides session management functionality
type SessionService interface {
	TrackSession(userID uint, token string, sessionType SessionType, ipAddress, userAgent string, expiresAt time.Time) error

	TrackJWTSessionWithJTI(userID uint, accessJTI, refreshJTI string, ipAddress, userAgent string, expiresAt time.Time) error

	UpdateJWTSession(oldRefreshJTI, newAccessJTI, newRefreshJTI string, expiresAt time.Time) error

	GetJWTSessionByRefreshJTI(refreshJTI string) (*UserSession, error)

	UpdateLastUsed(token string) error

	GetUserSessions(userID uint, currentToken string) ([]UserSession, error)

	RevokeSession(userID uint, sessionID uint) error

	RevokeAllOtherSessions(userID uint, currentToken string) error

	CleanupExpiredSessions() error

	SessionExists(token string) (bool, error)

	RemoveSessionByToken(token string) error
}
