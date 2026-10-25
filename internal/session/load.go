package session

import (
	"log/slog"
	"net/http"
	"time"
)

func (a *Auth) load(r *http.Request) (Session, StoreKey, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return Session{}, "", ErrNoSession
	}

	key := asStoreKey(c.Value)
	s, err := a.store.Load(r.Context(), key)
	if err != nil {
		return Session{}, "", err
	}

	now := a.now()
	if now.Sub(s.LastSeen) >= time.Minute {
		s.LastSeen = now
		if err := a.store.Save(r.Context(), key, s, deadline(s, a.sessionIdle, a.sessionMaxAge)); err != nil {
			slog.WarnContext(r.Context(), "Session idle deadline not extended", "error", err)
		}
	}

	return s, key, nil
}
