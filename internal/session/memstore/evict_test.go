package memstore

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/session"
)

var signedIn = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func save(t *testing.T, s *Store, key session.StoreKey, expiresAt time.Time) {
	t.Helper()
	if err := s.Save(t.Context(), key, session.Session{Subject: string(key)}, expiresAt); err != nil {
		t.Fatalf("Save(%q) error = %v", key, err)
	}
}

func TestEvictExpiredRemovesOnlyExpiredEntries(t *testing.T) {
	now := signedIn
	s := New(func() time.Time { return now })
	save(t, s, "expired", signedIn.Add(time.Hour))
	save(t, s, "at-deadline", signedIn.Add(90*time.Minute))
	save(t, s, "live", signedIn.Add(2*time.Hour))

	now = signedIn.Add(90 * time.Minute)
	s.evictExpired(t.Context())

	if len(s.sessions) != 1 {
		t.Fatalf("%d entries left, want only the live one: %v", len(s.sessions), s.sessions)
	}
	if _, ok := s.sessions["live"]; !ok {
		t.Errorf("the live entry was evicted, left: %v", s.sessions)
	}
}

func TestEvictExpiredOnAnEmptyStore(t *testing.T) {
	s := New(func() time.Time { return signedIn })
	s.evictExpired(t.Context())
	if len(s.sessions) != 0 {
		t.Errorf("%d entries in a store nothing was saved to", len(s.sessions))
	}
}

// Ranging over the map without the lock is a fatal error in Go, not a recoverable panic.
func TestEvictExpiredWhileSaving(t *testing.T) {
	s := New(func() time.Time { return signedIn })
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 2000 {
			key := session.StoreKey(fmt.Sprint(i))
			if err := s.Save(t.Context(), key, session.Session{}, signedIn.Add(time.Hour)); err != nil {
				t.Errorf("Save(%q) error = %v", key, err)
			}
		}
	})
	wg.Go(func() {
		for range 200 {
			s.evictExpired(t.Context())
		}
	})
	wg.Wait()
}
