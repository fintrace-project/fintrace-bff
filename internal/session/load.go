package session

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

const (
	refreshLag    = time.Minute
	touchInterval = time.Minute
)

func (a *Auth) load(r *http.Request) (Session, StoreKey, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return Session{}, "", ErrNoSession
	}

	key := asStoreKey(c.Value)
	// Shared by every request of this session in flight, so one disconnecting must not cancel it for the rest
	ctx := context.WithoutCancel(r.Context())
	v, err, _ := a.sessionLoads.Do(string(key), func() (any, error) {
		return a.loadAndUpdate(ctx, key)
	})
	if err != nil {
		return Session{}, "", err
	}
	return v.(Session), key, nil
}

func (a *Auth) loadAndUpdate(ctx context.Context, key StoreKey) (Session, error) {
	s, err := a.store.Load(ctx, key)
	if err != nil {
		return Session{}, err
	}

	now := a.now()
	switch {
	case needsRefresh(s, now):
		refreshed, err := a.refreshSession(ctx, s, now)
		if errors.Is(err, ErrNoSession) {
			a.dropSession(ctx, key)
			return Session{}, err
		}
		if err != nil {
			if now.Before(s.AccessExpiry) {
				// The access token still works, so a realm outage costs nothing until it lapses; the next request retries
				return s, nil
			}
			return Session{}, err
		}
		s = refreshed
	case now.Sub(s.LastSeen) < touchInterval:
		return s, nil
	}

	s.LastSeen = now
	if err := a.store.Save(ctx, key, s, deadline(s, a.sessionIdle, a.sessionMaxAge)); err != nil {
		slog.ErrorContext(ctx, "Session not saved", "sub", s.Subject, "error", err)
	}
	return s, nil
}

func needsRefresh(s Session, now time.Time) bool {
	return !now.Before(s.AccessExpiry.Add(-refreshLag))
}

func (a *Auth) dropSession(ctx context.Context, key StoreKey) {
	if err := a.store.Delete(ctx, key); err != nil {
		slog.WarnContext(ctx, "Session not deleted", "error", err)
	}
}
