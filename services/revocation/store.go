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
	JTI       string         `json:"jti" gorm:"uniqueIndex;size:50;not null"`
	ExpiresAt time.Time      `json:"expires_at" gorm:"not null"`
}

type Store interface {
	RevokeToken(jti string, expiresAt time.Time) error

	IsRevoked(jti string) (bool, error)

	CleanupExpiredTokens() error

	RevokeAllUserTokens(userID uint, issuedBefore time.Time) error

	LoadFromDatabase() error

	SaveToDatabase() error
}

type MemoryStore struct {
	mu            sync.RWMutex
	revokedTokens map[string]time.Time // JTI -> expiry time
	userTokens    map[uint][]string    // User ID -> JTI list
	db            *gorm.DB
	logger        *logging.Service
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		revokedTokens: make(map[string]time.Time),
		userTokens:    make(map[uint][]string),
	}
}

func NewMemoryStoreWithDB(db *gorm.DB, logger *logging.Service) *MemoryStore {
	return &MemoryStore{
		revokedTokens: make(map[string]time.Time),
		userTokens:    make(map[uint][]string),
		db:            db,
		logger:        logger,
	}
}

func (m *MemoryStore) RevokeToken(jti string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.revokedTokens[jti] = expiresAt

	if m.logger != nil {
		m.logger.Info("token revoked by JTI in memory",
			zap.String("jti", jti),
			zap.Time("expires_at", expiresAt),
			zap.Int("total_revoked_tokens", len(m.revokedTokens)))
	}

	if m.db != nil {
		revokedToken := RevokedToken{
			JTI:       jti,
			ExpiresAt: expiresAt,
		}
		if err := m.db.Create(&revokedToken).Error; err != nil {
			if m.logger != nil {
				m.logger.Error("failed to save revoked JTI to database",
					zap.String("jti", jti),
					zap.Error(err))
			}
			return err
		}
		if m.logger != nil {
			m.logger.Info("JTI saved to database",
				zap.String("jti", jti),
				zap.Time("expires_at", expiresAt))
		}
	}

	return nil
}

func (m *MemoryStore) IsRevoked(jti string) (bool, error) {
	m.mu.RLock()
	expiresAt, exists := m.revokedTokens[jti]
	m.mu.RUnlock()

	if !exists {
		if m.logger != nil {
			m.logger.Debug("JTI not found in revocation list",
				zap.String("jti", jti))
		}
		return false, nil
	}

	if time.Now().After(expiresAt) {
		m.mu.Lock()
		delete(m.revokedTokens, jti)
		m.mu.Unlock()

		if m.logger != nil {
			m.logger.Info("expired JTI removed from memory during lookup",
				zap.String("jti", jti),
				zap.Time("expired_at", expiresAt))
		}
		return false, nil
	}

	if m.logger != nil {
		m.logger.Debug("JTI found in revocation list",
			zap.String("jti", jti),
			zap.Time("expires_at", expiresAt))
	}

	return true, nil
}

func (m *MemoryStore) CleanupExpiredTokens() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	expiredJTICount := 0

	for jti, expiresAt := range m.revokedTokens {
		if now.After(expiresAt) {
			delete(m.revokedTokens, jti)
			expiredJTICount++
			if m.logger != nil {
				m.logger.Debug("expired JTI cleaned from memory",
					zap.String("jti", jti),
					zap.Time("expired_at", expiresAt))
			}
		}
	}

	if m.logger != nil && expiredJTICount > 0 {
		m.logger.Info("cleaned up expired JTIs from memory",
			zap.Int("expired_jtis", expiredJTICount),
			zap.Int("remaining_revoked_tokens", len(m.revokedTokens)))
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
		m.revokedTokens[token.JTI] = token.ExpiresAt
		loadedCount++
		if m.logger != nil {
			m.logger.Debug("JTI loaded into memory from database",
				zap.String("jti", token.JTI),
				zap.Time("expires_at", token.ExpiresAt))
		}
	}

	if m.logger != nil {
		m.logger.Info("JTIs loaded from database",
			zap.Int64("total_in_db", totalCount),
			zap.Int("loaded_count", loadedCount),
			zap.Int("total_memory_tokens", len(m.revokedTokens)))
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

	for jti, expiresAt := range m.revokedTokens {
		if now.Before(expiresAt) {
			tokensToSave = append(tokensToSave, RevokedToken{
				JTI:       jti,
				ExpiresAt: expiresAt,
			})
			if m.logger != nil {
				m.logger.Debug("JTI prepared for database save",
					zap.String("jti", jti),
					zap.Time("expires_at", expiresAt))
			}
		} else {
			expiredInMemory++
			if m.logger != nil {
				m.logger.Debug("expired JTI skipped during save",
					zap.String("jti", jti),
					zap.Time("expired_at", expiresAt))
			}
		}
	}

	if m.logger != nil {
		m.logger.Info("saving JTIs to database",
			zap.Int("total_memory_tokens", len(m.revokedTokens)),
			zap.Int("active_jtis_to_save", len(tokensToSave)),
			zap.Int("expired_in_memory", expiredInMemory))
	}

	if len(tokensToSave) == 0 {
		if m.logger != nil {
			m.logger.Info("no active JTIs to save to database")
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
				m.logger.Error("failed to save JTI to database",
					zap.String("jti", token.JTI),
					zap.Error(err))
			}
			return err
		}
		savedCount++
		if m.logger != nil {
			m.logger.Debug("JTI saved to database",
				zap.String("jti", token.JTI),
				zap.Time("expires_at", token.ExpiresAt))
		}
	}

	if err := tx.Commit().Error; err != nil {
		if m.logger != nil {
			m.logger.Error("failed to commit JTI save transaction", zap.Error(err))
		}
		return err
	}

	if m.logger != nil {
		m.logger.Info("successfully saved JTIs to database",
			zap.Int("saved_count", savedCount))
	}

	return nil
}
