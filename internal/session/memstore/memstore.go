package memstore

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/session"
)

type Store struct {
	mu       sync.Mutex
	sessions map[session.StoreKey]entry
	now      func() time.Time
}

var _ session.Store = (*Store)(nil) // Compile-time interface implementation check

type entry struct {
	session   session.Session
	expiresAt time.Time
}

func (s *Store) Save(_ context.Context, key session.StoreKey, sn session.Session, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[key] = entry{session: sn, expiresAt: expiresAt}
	return nil
}

func (s *Store) Load(_ context.Context, key session.StoreKey) (session.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.sessions[key]
	if !ok {
		return session.Session{}, session.ErrNoSession
	}
	if !s.now().Before(e.expiresAt) {
		delete(s.sessions, key)
		return session.Session{}, session.ErrNoSession
	}
	return e.session, nil
}

func (s *Store) Delete(_ context.Context, key session.StoreKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, key)
	return nil
}

func (s *Store) evictExpired(ctx context.Context) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	evicted := 0
	for key, e := range s.sessions {
		if !now.Before(e.expiresAt) {
			delete(s.sessions, key)
			evicted++
		}
	}
	if evicted > 0 {
		slog.InfoContext(ctx, "Expired sessions evicted", "count", evicted)
	}
}

func (s *Store) RunEviction(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.evictExpired(ctx)
		}
	}
}

func New(now func() time.Time) *Store {
	return &Store{
		sessions: make(map[session.StoreKey]entry),
		now:      now,
	}
}
