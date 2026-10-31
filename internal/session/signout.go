package session

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/fintrace-project/fintrace-bff/internal/logging"
)

func (a *Auth) SignOut(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(sessionCookie)
	http.SetCookie(w, configureSecureCookie(sessionCookie, "", -1)) // Clean session cookie explicitly
	w.Header().Set("Cache-Control", "no-store")

	ctx := r.Context()
	idToken := ""
	if c != nil && c.Value != "" {
		key := asStoreKey(c.Value)
		s, err := a.store.Load(ctx, key)

		if err != nil && !errors.Is(err, ErrNoSession) {
			slog.ErrorContext(ctx, "Session not loaded", "error", err)
			http.Error(w, "sign-out unavailable", http.StatusServiceUnavailable)
			return
		}
		ctx = logging.WithUserID(ctx, s.UserID)
		if err := a.store.Delete(ctx, key); err != nil {
			slog.WarnContext(ctx, "Session not deleted", "error", err)
		}
		idToken = s.IDToken
	}

	u := *a.oidc.EndSessionURL
	q := u.Query()
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	q.Set("post_logout_redirect_uri", a.oidc.PostLogoutRedirectURL)
	q.Set("client_id", a.oidc.OAuth2.ClientID)
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusSeeOther)
	// Sign-in never stores a session without its ID token, so none means no session was found
	if idToken != "" {
		slog.InfoContext(ctx, "Signed out")
	} else {
		slog.InfoContext(ctx, "Signed out without a session")
	}
}
