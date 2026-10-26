package session

import (
	"errors"
	"log/slog"
	"net/http"
)

func (a *Auth) SignOut(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(sessionCookie)
	http.SetCookie(w, configureSecureCookie(sessionCookie, "", -1)) // Clean session cookie explicitly
	w.Header().Set("Cache-Control", "no-store")

	idToken := ""
	sub := ""
	if c != nil && c.Value != "" {
		key := asStoreKey(c.Value)
		s, err := a.store.Load(r.Context(), key)

		if err != nil && !errors.Is(err, ErrNoSession) {
			slog.ErrorContext(r.Context(), "Session not loaded", "error", err)
			http.Error(w, "sign-out unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := a.store.Delete(r.Context(), key); err != nil {
			slog.WarnContext(r.Context(), "Session not deleted", "error", err)
		}
		idToken = s.IDToken
		sub = s.Subject
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
	if sub != "" {
		slog.InfoContext(r.Context(), "Signed out", "sub", sub)
	} else {
		slog.InfoContext(r.Context(), "Signed out without a session")
	}
}
