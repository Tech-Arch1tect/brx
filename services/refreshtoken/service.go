package refreshtoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

var (
	ErrRefreshTokenNotFound  = errors.New("refresh token not found")
	ErrRefreshTokenExpired   = errors.New("refresh token expired")
	ErrRefreshTokenInvalid   = errors.New("invalid refresh token")
	ErrTokenGenerationFailed = errors.New("failed to generate secure token")
)

type Service struct {
	db     *gorm.DB
	config *config.Config
	logger *logging.Service
}

type RefreshTokenService interface {
	GenerateRefreshToken(userID uint, sessionInfo TokenSessionInfo) (*RefreshTokenData, error)
	ValidateRefreshToken(tokenString string) (*RefreshToken, error)
	ValidateAndRotateRefreshToken(tokenString string, jwtService JWTService) (*TokenRotationResult, error)
	RevokeRefreshToken(tokenString string) error
	RevokeRefreshTokenByID(refreshTokenID uint) error
	RevokeAllUserRefreshTokens(userID uint) error
	GetRefreshTokenByHash(hash string) (*RefreshToken, error)
	UpdateLastUsed(tokenID uint) error
	CleanupExpiredTokens() error
}

type JWTService interface {
	GenerateToken(userID uint) (string, error)
	ExtractJTI(tokenString string) (string, error)
}

func NewService(db *gorm.DB, config *config.Config, logger *logging.Service) *Service {
	if logger != nil {
		logger.Info("initializing refresh token service",
			zap.Duration("token_expiry", config.RefreshToken.Expiry),
			zap.Int("token_length", config.RefreshToken.TokenLength),
			zap.Duration("cleanup_interval", config.RefreshToken.CleanupInterval))
	}

	return &Service{
		db:     db,
		config: config,
		logger: logger,
	}
}

func (s *Service) GenerateRefreshToken(userID uint, sessionInfo TokenSessionInfo) (*RefreshTokenData, error) {
	if s.logger != nil {
		s.logger.Debug("generating refresh token",
			zap.Uint("user_id", userID))
	}

	token, err := s.generateSecureToken()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate secure refresh token", zap.Error(err))
		}
		return nil, ErrTokenGenerationFailed
	}

	tokenHash := s.hashToken(token)
	expiresAt := time.Now().Add(s.config.RefreshToken.Expiry)

	deviceInfoJSON := ""
	if sessionInfo.DeviceInfo != nil {
		if jsonBytes, err := json.Marshal(sessionInfo.DeviceInfo); err == nil {
			deviceInfoJSON = string(jsonBytes)
		}
	}

	refreshToken := RefreshToken{
		UserID:     userID,
		TokenHash:  tokenHash,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
		DeviceInfo: deviceInfoJSON,
	}

	if err := s.db.Create(&refreshToken).Error; err != nil {
		if s.logger != nil {
			s.logger.Error("failed to store refresh token", zap.Error(err))
		}
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("refresh token generated successfully",
			zap.Uint("user_id", userID),
			zap.Uint("token_id", refreshToken.ID),
			zap.Time("expires_at", expiresAt))
	}

	return &RefreshTokenData{
		Token:     token,
		TokenID:   refreshToken.ID,
		Hash:      tokenHash,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) ValidateRefreshToken(tokenString string) (*RefreshToken, error) {
	if s.logger != nil {
		s.logger.Debug("validating refresh token")
	}

	tokenHash := s.hashToken(tokenString)

	var refreshToken RefreshToken
	err := s.db.Where("token_hash = ?", tokenHash).First(&refreshToken).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if s.logger != nil {
				s.logger.Warn("refresh token validation failed - token not found")
			}
			return nil, ErrRefreshTokenNotFound
		}
		if s.logger != nil {
			s.logger.Error("refresh token validation failed - database error",
				zap.Error(err))
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		if s.logger != nil {
			s.logger.Warn("refresh token validation failed - token expired",
				zap.Uint("token_id", refreshToken.ID),
				zap.Uint("user_id", refreshToken.UserID),
				zap.Time("expired_at", refreshToken.ExpiresAt))
		}
		s.db.Delete(&refreshToken)
		return nil, ErrRefreshTokenExpired
	}

	if s.logger != nil {
		s.logger.Debug("refresh token validated successfully",
			zap.Uint("token_id", refreshToken.ID),
			zap.Uint("user_id", refreshToken.UserID))
	}

	return &refreshToken, nil
}

func (s *Service) ValidateAndRotateRefreshToken(tokenString string, jwtService JWTService) (*TokenRotationResult, error) {
	if s.logger != nil {
		s.logger.Info("starting refresh token rotation")
	}

	oldToken, err := s.ValidateRefreshToken(tokenString)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("refresh token rotation failed - validation error",
				zap.Error(err))
		}
		return nil, err
	}

	newAccessToken, err := jwtService.GenerateToken(oldToken.UserID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("refresh token rotation failed - access token generation error",
				zap.Error(err),
				zap.Uint("user_id", oldToken.UserID))
		}
		return nil, fmt.Errorf("failed to generate new access token: %w", err)
	}

	sessionInfo := TokenSessionInfo{}
	if oldToken.DeviceInfo != "" {
		var deviceInfo map[string]any
		if err := json.Unmarshal([]byte(oldToken.DeviceInfo), &deviceInfo); err == nil {
			sessionInfo.DeviceInfo = deviceInfo
		}
	}

	newRefreshTokenData, err := s.GenerateRefreshToken(oldToken.UserID, sessionInfo)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("refresh token rotation failed - new token generation error",
				zap.Error(err),
				zap.Uint("user_id", oldToken.UserID))
		}
		return nil, fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	if err := s.db.Delete(oldToken).Error; err != nil {
		if s.logger != nil {
			s.logger.Warn("failed to delete old refresh token during rotation",
				zap.Uint("token_id", oldToken.ID),
				zap.Error(err))
		}
	}

	if s.logger != nil {
		s.logger.Info("refresh token rotation completed successfully",
			zap.Uint("user_id", oldToken.UserID),
			zap.Uint("old_token_id", oldToken.ID),
			zap.Uint("new_token_id", newRefreshTokenData.TokenID))
	}

	return &TokenRotationResult{
		AccessToken:     newAccessToken,
		RefreshToken:    newRefreshTokenData.Token,
		RefreshTokenID:  newRefreshTokenData.TokenID,
		OldTokenID:      oldToken.ID,
		ExpiresAt:       newRefreshTokenData.ExpiresAt,
		OldTokenRevoked: true,
	}, nil
}

func (s *Service) RevokeRefreshToken(tokenString string) error {
	if s.logger != nil {
		s.logger.Info("revoking refresh token")
	}

	tokenHash := s.hashToken(tokenString)
	result := s.db.Where("token_hash = ?", tokenHash).Delete(&RefreshToken{})

	if result.Error != nil {
		if s.logger != nil {
			s.logger.Error("failed to revoke refresh token",
				zap.Error(result.Error))
		}
		return fmt.Errorf("failed to revoke refresh token: %w", result.Error)
	}

	if s.logger != nil {
		s.logger.Info("refresh token revoked successfully",
			zap.String("token_hash", tokenHash[:16]+"..."),
			zap.Int64("affected_rows", result.RowsAffected))
	}

	return nil
}

func (s *Service) RevokeRefreshTokenByID(refreshTokenID uint) error {
	if s.logger != nil {
		s.logger.Info("revoking refresh token by ID",
			zap.Uint("refresh_token_id", refreshTokenID))
	}

	result := s.db.Where("id = ?", refreshTokenID).Delete(&RefreshToken{})

	if result.Error != nil {
		if s.logger != nil {
			s.logger.Error("failed to revoke refresh token by ID",
				zap.Error(result.Error),
				zap.Uint("refresh_token_id", refreshTokenID))
		}
		return fmt.Errorf("failed to revoke refresh token by ID: %w", result.Error)
	}

	if s.logger != nil {
		s.logger.Info("refresh token revoked successfully by ID",
			zap.Uint("refresh_token_id", refreshTokenID),
			zap.Int64("affected_rows", result.RowsAffected))
	}

	return nil
}

func (s *Service) RevokeAllUserRefreshTokens(userID uint) error {
	if s.logger != nil {
		s.logger.Info("revoking all user refresh tokens",
			zap.Uint("user_id", userID))
	}

	result := s.db.Where("user_id = ?", userID).Delete(&RefreshToken{})

	if result.Error != nil {
		if s.logger != nil {
			s.logger.Error("failed to revoke all user refresh tokens",
				zap.Error(result.Error),
				zap.Uint("user_id", userID))
		}
		return fmt.Errorf("failed to revoke all user refresh tokens: %w", result.Error)
	}

	if s.logger != nil {
		s.logger.Info("all user refresh tokens revoked",
			zap.Uint("user_id", userID),
			zap.Int64("count", result.RowsAffected))
	}

	return nil
}

func (s *Service) GetRefreshTokenByHash(hash string) (*RefreshToken, error) {
	if s.logger != nil {
		s.logger.Debug("retrieving refresh token by hash")
	}

	var refreshToken RefreshToken
	err := s.db.Where("token_hash = ?", hash).First(&refreshToken).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if s.logger != nil {
				s.logger.Debug("refresh token not found by hash")
			}
			return nil, ErrRefreshTokenNotFound
		}
		if s.logger != nil {
			s.logger.Error("failed to retrieve refresh token by hash",
				zap.Error(err))
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	if s.logger != nil {
		s.logger.Debug("refresh token retrieved successfully by hash",
			zap.Uint("token_id", refreshToken.ID),
			zap.Uint("user_id", refreshToken.UserID))
	}

	return &refreshToken, nil
}

func (s *Service) UpdateLastUsed(tokenID uint) error {
	err := s.db.Model(&RefreshToken{}).
		Where("id = ?", tokenID).
		Update("last_used", time.Now()).Error

	if err != nil && s.logger != nil {
		s.logger.Warn("failed to update refresh token last used time",
			zap.Error(err),
			zap.Uint("token_id", tokenID))
	}

	return err
}

func (s *Service) CleanupExpiredTokens() error {
	if s.logger != nil {
		s.logger.Debug("starting expired refresh tokens cleanup")
	}

	var expiredTokenIDs []uint
	err := s.db.Model(&RefreshToken{}).
		Where("expires_at < ?", time.Now()).
		Pluck("id", &expiredTokenIDs).Error

	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to query expired refresh token IDs", zap.Error(err))
		}
		return fmt.Errorf("failed to query expired token IDs: %w", err)
	}

	result := s.db.Where("expires_at < ?", time.Now()).Delete(&RefreshToken{})

	if result.Error != nil {
		if s.logger != nil {
			s.logger.Error("failed to cleanup expired refresh tokens", zap.Error(result.Error))
		}
		return fmt.Errorf("failed to cleanup expired tokens: %w", result.Error)
	}

	if len(expiredTokenIDs) > 0 {

		sessionResult := s.db.Exec("DELETE FROM user_sessions WHERE refresh_token_id IN ?", expiredTokenIDs)

		if sessionResult.Error != nil {
			if s.logger != nil {
				s.logger.Warn("failed to cleanup sessions for expired refresh tokens",
					zap.Error(sessionResult.Error),
					zap.Uints("refresh_token_ids", expiredTokenIDs))
			}

		} else if s.logger != nil && sessionResult.RowsAffected > 0 {
			s.logger.Info("cleaned up sessions for expired refresh tokens",
				zap.Int64("session_count", sessionResult.RowsAffected),
				zap.Int("refresh_token_count", len(expiredTokenIDs)))
		}
	}

	if s.logger != nil {
		if result.RowsAffected > 0 {
			s.logger.Info("cleaned up expired refresh tokens",
				zap.Int64("count", result.RowsAffected))
		} else {
			s.logger.Debug("no expired refresh tokens found to cleanup")
		}
	}

	return nil
}

func (s *Service) generateSecureToken() (string, error) {
	tokenBytes := make([]byte, s.config.RefreshToken.TokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tokenBytes), nil
}

func (s *Service) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *Service) StartCleanupWorker() {
	go func() {
		ticker := time.NewTicker(s.config.RefreshToken.CleanupInterval)
		defer ticker.Stop()

		for range ticker.C {
			if err := s.CleanupExpiredTokens(); err != nil && s.logger != nil {
				s.logger.Error("refresh token cleanup worker failed", zap.Error(err))
			}
		}
	}()

	if s.logger != nil {
		s.logger.Info("started refresh token cleanup worker",
			zap.Duration("interval", s.config.RefreshToken.CleanupInterval))
	}
}
