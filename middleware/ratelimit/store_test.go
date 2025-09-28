package ratelimit

import (
	"testing"
	"time"
)

func TestMemoryStore(t *testing.T) {
	t.Run("NewMemoryStore", func(t *testing.T) {
		store := NewMemoryStore()
		if store == nil {
			t.Fatal("expected store to be created")
		}
		if store.data == nil {
			t.Error("expected data map to be initialized")
		}
	})

	t.Run("Get non-existent key", func(t *testing.T) {
		store := NewMemoryStore()
		count, resetTime, exists := store.Get("non-existent")

		if exists {
			t.Error("expected key to not exist")
		}
		if count != 0 {
			t.Errorf("expected count 0, got %d", count)
		}
		if !resetTime.IsZero() {
			t.Error("expected zero time")
		}
	})

	t.Run("Set and Get", func(t *testing.T) {
		store := NewMemoryStore()
		key := "test-key"
		expectedCount := 5
		expectedResetTime := time.Now().Add(time.Minute)

		store.Set(key, expectedCount, expectedResetTime)

		count, resetTime, exists := store.Get(key)
		if !exists {
			t.Error("expected key to exist")
		}
		if count != expectedCount {
			t.Errorf("expected count %d, got %d", expectedCount, count)
		}
		if !resetTime.Equal(expectedResetTime) {
			t.Errorf("expected reset time %v, got %v", expectedResetTime, resetTime)
		}
	})

	t.Run("Get expired entry", func(t *testing.T) {
		store := NewMemoryStore()
		key := "expired-key"
		pastTime := time.Now().Add(-time.Minute)

		store.Set(key, 5, pastTime)

		count, resetTime, exists := store.Get(key)
		if exists {
			t.Error("expected expired key to not exist")
		}
		if count != 0 {
			t.Errorf("expected count 0, got %d", count)
		}
		if !resetTime.IsZero() {
			t.Error("expected zero time")
		}
	})

	t.Run("Increment new key", func(t *testing.T) {
		store := NewMemoryStore()
		key := "increment-key"
		resetTime := time.Now().Add(time.Minute)

		count := store.Increment(key, resetTime)
		if count != 1 {
			t.Errorf("expected count 1, got %d", count)
		}

		storedCount, storedResetTime, exists := store.Get(key)
		if !exists {
			t.Error("expected key to exist after increment")
		}
		if storedCount != 1 {
			t.Errorf("expected stored count 1, got %d", storedCount)
		}
		if !storedResetTime.Equal(resetTime) {
			t.Errorf("expected reset time %v, got %v", resetTime, storedResetTime)
		}
	})

	t.Run("Increment existing key", func(t *testing.T) {
		store := NewMemoryStore()
		key := "increment-existing"
		resetTime := time.Now().Add(time.Minute)

		store.Set(key, 3, resetTime)

		count := store.Increment(key, resetTime)
		if count != 4 {
			t.Errorf("expected count 4, got %d", count)
		}

		storedCount, _, exists := store.Get(key)
		if !exists {
			t.Error("expected key to exist")
		}
		if storedCount != 4 {
			t.Errorf("expected stored count 4, got %d", storedCount)
		}
	})

	t.Run("Increment expired key", func(t *testing.T) {
		store := NewMemoryStore()
		key := "increment-expired"
		pastTime := time.Now().Add(-time.Minute)
		futureTime := time.Now().Add(time.Minute)

		store.Set(key, 10, pastTime)

		count := store.Increment(key, futureTime)
		if count != 1 {
			t.Errorf("expected count 1, got %d", count)
		}
	})

	t.Run("Reset", func(t *testing.T) {
		store := NewMemoryStore()
		key := "reset-key"
		resetTime := time.Now().Add(time.Minute)

		store.Set(key, 5, resetTime)

		_, _, exists := store.Get(key)
		if !exists {
			t.Error("expected key to exist before reset")
		}

		store.Reset(key)

		_, _, exists = store.Get(key)
		if exists {
			t.Error("expected key to not exist after reset")
		}
	})

	t.Run("Reset non-existent key", func(t *testing.T) {
		store := NewMemoryStore()

		store.Reset("non-existent")
	})

	t.Run("concurrent access", func(t *testing.T) {
		store := NewMemoryStore()
		key := "concurrent-key"
		resetTime := time.Now().Add(time.Minute)

		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func() {
				store.Increment(key, resetTime)
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}

		count, _, exists := store.Get(key)
		if !exists {
			t.Error("expected key to exist")
		}
		if count != 10 {
			t.Errorf("expected count 10, got %d", count)
		}
	})
}
