package revocation

import (
	"sync"
	"time"
)

type Store interface {
	RevokeToken(token string, expiresAt time.Time) error

	IsRevoked(token string) (bool, error)

	CleanupExpiredTokens() error

	RevokeAllUserTokens(userID uint, issuedBefore time.Time) error
}

type MemoryStore struct {
	mu      sync.RWMutex
	tokens  map[string]time.Time
	userMap map[uint][]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tokens:  make(map[string]time.Time),
		userMap: make(map[uint][]string),
	}
}

func (m *MemoryStore) RevokeToken(token string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tokens[token] = expiresAt
	return nil
}

func (m *MemoryStore) IsRevoked(token string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	expiresAt, exists := m.tokens[token]
	if !exists {
		return false, nil
	}

	if time.Now().After(expiresAt) {
		delete(m.tokens, token)
		return false, nil
	}

	return true, nil
}

func (m *MemoryStore) CleanupExpiredTokens() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for token, expiresAt := range m.tokens {
		if now.After(expiresAt) {
			delete(m.tokens, token)
		}
	}

	return nil
}

func (m *MemoryStore) RevokeAllUserTokens(userID uint, issuedBefore time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return nil
}
