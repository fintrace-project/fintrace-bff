package session

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/httperr"
	"github.com/fintrace-project/fintrace-bff/internal/logging"
)

type sessionInfo struct {
	UserID    string    `json:"userId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (a *Auth) SessionState(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		httperr.Write(w, r, http.StatusUnauthorized, httperr.NoSession, "no session")
		return
	}

	// Straight from the store, never through load: a read must not refresh or move LastSeen
	s, err := a.store.Load(r.Context(), asStoreKey(c.Value))
	if errors.Is(err, ErrNoSession) {
		httperr.Write(w, r, http.StatusUnauthorized, httperr.NoSession, "no session")
		return
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "Session not loaded", "error", err)
		httperr.Write(w, r, http.StatusServiceUnavailable, httperr.SessionUnavailable, "session store unavailable")
		return
	}

	ctx := logging.WithUserID(r.Context(), s.UserID)
	info := sessionInfo{UserID: s.UserID, ExpiresAt: deadline(s, a.sessionIdle, a.sessionMaxAge).UTC()}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		slog.WarnContext(ctx, "Session info not written", "error", err)
	}
}
