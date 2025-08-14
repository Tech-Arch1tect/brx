package ratelimit

import (
	"sync"
	"time"
)

type Store interface {
	Get(key string) (count int, resetTime time.Time, exists bool)
	Set(key string, count int, resetTime time.Time)
	Increment(key string, resetTime time.Time) (count int)
	Reset(key string)
}

type MemoryStore struct {
	mu   sync.RWMutex
	data map[string]*entry
}

type entry struct {
	count     int
	resetTime time.Time
}

func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		data: make(map[string]*entry),
	}

	go store.cleanup()

	return store
}

func (s *MemoryStore) Get(key string) (count int, resetTime time.Time, exists bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if e, exists := s.data[key]; exists && time.Now().Before(e.resetTime) {
		return e.count, e.resetTime, true
	}

	return 0, time.Time{}, false
}

func (s *MemoryStore) Set(key string, count int, resetTime time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data[key] = &entry{
		count:     count,
		resetTime: resetTime,
	}
}

func (s *MemoryStore) Increment(key string, resetTime time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e, exists := s.data[key]; exists && time.Now().Before(e.resetTime) {
		e.count++
		return e.count
	}

	s.data[key] = &entry{
		count:     1,
		resetTime: resetTime,
	}

	return 1
}

func (s *MemoryStore) Reset(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, key)
}

func (s *MemoryStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()

		for key, entry := range s.data {
			if now.After(entry.resetTime) {
				delete(s.data, key)
			}
		}

		s.mu.Unlock()
	}
}
