package revocation

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/tech-arch1tect/brx/services/logging"
	"go.uber.org/zap"
)

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", hash[:8])
}

type RevokedToken struct {
	ID        uint           `json:"id" gorm:"primarykey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
	Token     string         `json:"token" gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time      `json:"expires_at" gorm:"not null"`
}

type Store interface {
	RevokeToken(token string, expiresAt time.Time) error

	IsRevoked(token string) (bool, error)

	CleanupExpiredTokens() error

	RevokeAllUserTokens(userID uint, issuedBefore time.Time) error

	LoadFromDatabase() error

	SaveToDatabase() error
}

type MemoryStore struct {
	mu      sync.RWMutex
	tokens  map[string]time.Time
	userMap map[uint][]string
	db      *gorm.DB
	logger  *logging.Service
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tokens:  make(map[string]time.Time),
		userMap: make(map[uint][]string),
	}
}

func NewMemoryStoreWithDB(db *gorm.DB, logger *logging.Service) *MemoryStore {
	return &MemoryStore{
		tokens:  make(map[string]time.Time),
		userMap: make(map[uint][]string),
		db:      db,
		logger:  logger,
	}
}

func (m *MemoryStore) RevokeToken(token string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tokens[token] = expiresAt

	if m.logger != nil {
		m.logger.Info("token revoked in memory",
			zap.String("token_hash", hashToken(token)),
			zap.Time("expires_at", expiresAt),
			zap.Int("total_memory_tokens", len(m.tokens)))
	}

	if m.db != nil {
		revokedToken := RevokedToken{
			Token:     token,
			ExpiresAt: expiresAt,
		}
		if err := m.db.Create(&revokedToken).Error; err != nil {
			if m.logger != nil {
				m.logger.Error("failed to save revoked token to database",
					zap.String("token_hash", hashToken(token)),
					zap.Error(err))
			}
			return err
		}
		if m.logger != nil {
			m.logger.Info("token saved to database",
				zap.String("token_hash", hashToken(token)),
				zap.Time("expires_at", expiresAt))
		}
	}

	return nil
}

func (m *MemoryStore) IsRevoked(token string) (bool, error) {
	m.mu.RLock()
	expiresAt, exists := m.tokens[token]
	m.mu.RUnlock()

	if !exists {
		if m.logger != nil {
			m.logger.Debug("token not found in revocation list",
				zap.String("token_hash", hashToken(token)))
		}
		return false, nil
	}

	if time.Now().After(expiresAt) {
		m.mu.Lock()
		delete(m.tokens, token)
		m.mu.Unlock()

		if m.logger != nil {
			m.logger.Info("expired token removed from memory during lookup",
				zap.String("token_hash", hashToken(token)),
				zap.Time("expired_at", expiresAt))
		}
		return false, nil
	}

	if m.logger != nil {
		m.logger.Debug("token found in revocation list",
			zap.String("token_hash", hashToken(token)),
			zap.Time("expires_at", expiresAt))
	}

	return true, nil
}

func (m *MemoryStore) CleanupExpiredTokens() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	expiredCount := 0

	for token, expiresAt := range m.tokens {
		if now.After(expiresAt) {
			delete(m.tokens, token)
			expiredCount++
			if m.logger != nil {
				m.logger.Debug("expired token cleaned from memory",
					zap.String("token_hash", hashToken(token)),
					zap.Time("expired_at", expiresAt))
			}
		}
	}

	if m.logger != nil && expiredCount > 0 {
		m.logger.Info("cleaned up expired tokens from memory",
			zap.Int("expired_count", expiredCount),
			zap.Int("remaining_tokens", len(m.tokens)))
	}

	return nil
}

func (m *MemoryStore) RevokeAllUserTokens(userID uint, issuedBefore time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return nil
}

func (m *MemoryStore) LoadFromDatabase() error {
	if m.db == nil {
		if m.logger != nil {
			m.logger.Debug("no database available for token loading")
		}
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	var totalCount int64
	if err := m.db.Model(&RevokedToken{}).Count(&totalCount).Error; err != nil {
		if m.logger != nil {
			m.logger.Error("failed to count total tokens in database", zap.Error(err))
		}
		return err
	}

	var revokedTokens []RevokedToken
	if err := m.db.Where("expires_at > ?", now).Find(&revokedTokens).Error; err != nil {
		if m.logger != nil {
			m.logger.Error("failed to load tokens from database", zap.Error(err))
		}
		return err
	}

	loadedCount := 0
	for _, token := range revokedTokens {
		m.tokens[token.Token] = token.ExpiresAt
		loadedCount++
		if m.logger != nil {
			m.logger.Debug("token loaded into memory from database",
				zap.String("token_hash", hashToken(token.Token)),
				zap.Time("expires_at", token.ExpiresAt))
		}
	}

	if m.logger != nil {
		m.logger.Info("tokens loaded from database",
			zap.Int64("total_in_db", totalCount),
			zap.Int("loaded_count", loadedCount),
			zap.Int("total_memory_tokens", len(m.tokens)))
	}

	var expiredCount int64
	result := m.db.Unscoped().Where("expires_at <= ?", now).Delete(&RevokedToken{})
	if result.Error != nil {
		if m.logger != nil {
			m.logger.Error("failed to clean expired tokens from database", zap.Error(result.Error))
		}
		return result.Error
	}
	expiredCount = result.RowsAffected

	if m.logger != nil && expiredCount > 0 {
		m.logger.Info("cleaned up expired tokens from database during load",
			zap.Int64("expired_count", expiredCount))
	}

	return nil
}

func (m *MemoryStore) SaveToDatabase() error {
	if m.db == nil {
		if m.logger != nil {
			m.logger.Debug("no database available for token saving")
		}
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	var tokensToSave []RevokedToken
	expiredInMemory := 0

	for token, expiresAt := range m.tokens {
		if now.Before(expiresAt) {
			tokensToSave = append(tokensToSave, RevokedToken{
				Token:     token,
				ExpiresAt: expiresAt,
			})
			if m.logger != nil {
				m.logger.Debug("token prepared for database save",
					zap.String("token_hash", hashToken(token)),
					zap.Time("expires_at", expiresAt))
			}
		} else {
			expiredInMemory++
			if m.logger != nil {
				m.logger.Debug("expired token skipped during save",
					zap.String("token_hash", hashToken(token)),
					zap.Time("expired_at", expiresAt))
			}
		}
	}

	if m.logger != nil {
		m.logger.Info("saving tokens to database",
			zap.Int("total_memory_tokens", len(m.tokens)),
			zap.Int("active_tokens_to_save", len(tokensToSave)),
			zap.Int("expired_in_memory", expiredInMemory))
	}

	if len(tokensToSave) == 0 {
		if m.logger != nil {
			m.logger.Info("no active tokens to save to database")
		}
		return nil
	}

	tx := m.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	expiredResult := tx.Unscoped().Where("expires_at <= ?", now).Delete(&RevokedToken{})
	if expiredResult.Error != nil {
		tx.Rollback()
		if m.logger != nil {
			m.logger.Error("failed to clean expired tokens before save", zap.Error(expiredResult.Error))
		}
		return expiredResult.Error
	}

	if m.logger != nil && expiredResult.RowsAffected > 0 {
		m.logger.Info("cleaned expired tokens from database before save",
			zap.Int64("expired_count", expiredResult.RowsAffected))
	}

	clearResult := tx.Unscoped().Delete(&RevokedToken{}, "1=1")
	if clearResult.Error != nil {
		tx.Rollback()
		if m.logger != nil {
			m.logger.Error("failed to clear existing tokens from database", zap.Error(clearResult.Error))
		}
		return clearResult.Error
	}

	if m.logger != nil {
		m.logger.Info("cleared all existing tokens from database",
			zap.Int64("cleared_count", clearResult.RowsAffected))
	}

	savedCount := 0
	for _, token := range tokensToSave {
		if err := tx.Create(&token).Error; err != nil {
			tx.Rollback()
			if m.logger != nil {
				m.logger.Error("failed to save token to database",
					zap.String("token_hash", hashToken(token.Token)),
					zap.Error(err))
			}
			return err
		}
		savedCount++
		if m.logger != nil {
			m.logger.Debug("token saved to database",
				zap.String("token_hash", hashToken(token.Token)),
				zap.Time("expires_at", token.ExpiresAt))
		}
	}

	if err := tx.Commit().Error; err != nil {
		if m.logger != nil {
			m.logger.Error("failed to commit token save transaction", zap.Error(err))
		}
		return err
	}

	if m.logger != nil {
		m.logger.Info("successfully saved tokens to database",
			zap.Int("saved_count", savedCount))
	}

	return nil
}
