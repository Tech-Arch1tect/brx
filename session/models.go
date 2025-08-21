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
	ID             uint        `json:"id" gorm:"primaryKey"`
	UserID         uint        `json:"user_id" gorm:"not null;index"`
	Token          string      `json:"token" gorm:"uniqueIndex;size:255;not null"`
	Type           SessionType `json:"type" gorm:"size:10;not null;default:'web'"`
	AccessTokenJTI string      `json:"-" gorm:"size:50;index"`
	RefreshTokenID uint        `json:"-" gorm:"index"`
	IPAddress      string      `json:"ip_address" gorm:"size:45"`
	UserAgent      string      `json:"user_agent" gorm:"size:500"`
	Current        bool        `json:"current" gorm:"-"`
	CreatedAt      time.Time   `json:"created_at"`
	LastUsed       time.Time   `json:"last_used"`
	ExpiresAt      time.Time   `json:"expires_at"`
}

func (UserSession) TableName() string {
	return "user_sessions"
}

// SessionService provides session management functionality
type SessionService interface {
	TrackSession(userID uint, token string, sessionType SessionType, ipAddress, userAgent string, expiresAt time.Time) error

	TrackJWTSessionWithRefreshToken(userID uint, accessJTI string, refreshTokenID uint, ipAddress, userAgent string, expiresAt time.Time) error

	UpdateJWTSessionWithRefreshToken(oldRefreshTokenID uint, newAccessJTI string, newRefreshTokenID uint, expiresAt time.Time) error

	GetJWTSessionByRefreshTokenID(refreshTokenID uint) (*UserSession, error)

	UpdateLastUsed(token string) error

	GetUserSessions(userID uint, currentToken string) ([]UserSession, error)

	RevokeSession(userID uint, sessionID uint) error

	RevokeAllOtherSessions(userID uint, currentToken string) error

	CleanupExpiredSessions() error

	SessionExists(token string) (bool, error)

	RemoveSessionByToken(token string) error
}
