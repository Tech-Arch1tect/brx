package revocation

import (
	"errors"
	"fmt"
	"time"

	"github.com/tech-arch1tect/brx/config"
	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/zap"
)

var (
	ErrRevocationDisabled = errors.New("JWT revocation is disabled")
	ErrInvalidToken       = errors.New("invalid JWT token")
	ErrStoreNotConfigured = errors.New("revocation store not configured")
)

type Service struct {
	config *config.Config
	store  Store
	logger *logging.Service
}

func NewService(cfg *config.Config, store Store, logger *logging.Service) *Service {
	return &Service{
		config: cfg,
		store:  store,
		logger: logger,
	}
}

func (s *Service) RevokeToken(jti string, expiresAt time.Time) error {
	if s.store == nil {
		return ErrStoreNotConfigured
	}

	err := s.store.RevokeToken(jti, expiresAt)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to revoke token by JTI", zap.String("jti", jti), zap.Error(err))
		}
		return fmt.Errorf("failed to revoke token by JTI: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("token revoked successfully by JTI",
			zap.String("jti", jti),
			zap.String("expires_at", expiresAt.Format(time.RFC3339)))
	}

	return nil
}

func (s *Service) IsTokenRevoked(jti string) (bool, error) {
	if s.store == nil {
		return false, ErrStoreNotConfigured
	}

	revoked, err := s.store.IsRevoked(jti)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to check JTI revocation status", zap.String("jti", jti), zap.Error(err))
		}
		return false, fmt.Errorf("failed to check JTI revocation status: %w", err)
	}

	return revoked, nil
}

func (s *Service) RevokeAllUserTokens(userID uint, issuedBefore time.Time) error {
	if s.store == nil {
		return ErrStoreNotConfigured
	}

	err := s.store.RevokeAllUserTokens(userID, issuedBefore)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to revoke all user tokens",
				zap.Uint("user_id", userID),
				zap.Error(err))
		}
		return fmt.Errorf("failed to revoke all user tokens: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("revoked all user tokens",
			zap.Uint("user_id", userID),
			zap.String("issued_before", issuedBefore.Format(time.RFC3339)))
	}

	return nil
}

func (s *Service) CleanupExpiredTokens() error {
	if s.store == nil {
		return ErrStoreNotConfigured
	}

	err := s.store.CleanupExpiredTokens()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to cleanup expired tokens", zap.Error(err))
		}
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	if s.logger != nil {
		s.logger.Debug("cleaned up expired tokens")
	}

	return nil
}

func (s *Service) StartCleanupWorker(interval time.Duration) {
	if s.store == nil {
		if s.logger != nil {
			s.logger.Warn("cannot start cleanup worker: store not configured")
		}
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			if err := s.CleanupExpiredTokens(); err != nil && s.logger != nil {
				s.logger.Error("cleanup worker failed", zap.Error(err))
			}
		}
	}()

	if s.logger != nil {
		s.logger.Info("started revocation cleanup worker",
			zap.Duration("interval", interval))
	}
}
