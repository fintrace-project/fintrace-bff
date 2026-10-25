package session

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	lcv := newLoginCookieValue()

	http.SetCookie(w, configureSecureCookie(loginCookie, lcv.cookieValue(), 300))

	loginURL := a.oidc.OAuth2.AuthCodeURL(lcv.state, oidc.Nonce(lcv.nonce), oauth2.S256ChallengeOption(lcv.verifier))
	w.Header().Set("Cache-Control", "no-store")

	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (a *Auth) Callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(loginCookie)
	http.SetCookie(w, configureSecureCookie(loginCookie, "", -1)) // Clean login cookie explicitly
	if err != nil {
		refuse(w, r, "Sign-in callback without a login cookie", err)
		return
	}

	lcv, err := parseLoginCookie(cookie)
	if err != nil {
		refuse(w, r, "Sign-in login cookie is malformed", err)
		return
	}

	query := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(lcv.state)) != 1 {
		refuse(w, r, "Sign-in state does not match", nil)
		return
	}
	if realmError := query.Get("error"); realmError != "" {
		refuse(w, r, "Sign-in refused by the realm",
			fmt.Errorf("%s: %s", realmError, query.Get("error_description")))
		return
	}

	code := query.Get("code")
	if code == "" {
		refuse(w, r, "Sign-in callback carries no code", nil)
		return
	}

	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, a.client)
	token, err := a.oidc.OAuth2.Exchange(ctx, code, oauth2.VerifierOption(lcv.verifier))
	if err != nil {
		refuse(w, r, "Sign-in code exchange failed", err)
		return
	}

	rawToken, ok := token.Extra("id_token").(string)
	if !ok || rawToken == "" {
		refuse(w, r, "Token response carries no ID token", nil)
		return
	}
	idToken, err := a.oidc.Verifier.Verify(ctx, rawToken)
	if err != nil {
		refuse(w, r, "Sign-in ID token rejected", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(lcv.nonce)) != 1 {
		refuse(w, r, "Sign-in nonce does not match", nil)
		return
	}

	a.completeLogin(w, r, idToken, token, rawToken)
}

func (a *Auth) completeLogin(w http.ResponseWriter, r *http.Request, idToken *oidc.IDToken, token *oauth2.Token, rawIDToken string) {
	if c, _ := r.Cookie(sessionCookie); c != nil && c.Value != "" {
		if err := a.store.Delete(r.Context(), asStoreKey(c.Value)); err != nil {
			slog.WarnContext(r.Context(), "Old session not deleted", "error", err)
		}
	}

	now := a.now()

	s := Session{
		Subject:       idToken.Subject,
		AccessToken:   token.AccessToken,
		RefreshToken:  token.RefreshToken,
		AccessExpiry:  token.Expiry,
		RefreshExpiry: refreshExpiry(token, now),
		IDToken:       rawIDToken,
		CreatedAt:     now,
		LastSeen:      now,
	}

	id := rand.Text()
	if err := a.store.Save(r.Context(), asStoreKey(id), s, deadline(s, a.sessionIdle, a.sessionMaxAge)); err != nil {
		slog.ErrorContext(r.Context(), "Session not saved", "error", err)
		http.Error(w, "sign-in unavailable", http.StatusServiceUnavailable)
		return
	}

	http.SetCookie(w, configureSecureCookie(sessionCookie, id, int(a.sessionMaxAge.Seconds())))

	slog.InfoContext(r.Context(), "Signed in", "sub", idToken.Subject)
	w.Header().Set("Cache-Control", "no-store")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func refreshExpiry(token *oauth2.Token, now time.Time) time.Time {
	secs, ok := token.Extra("refresh_expires_in").(float64)
	if !ok || secs <= 0 {
		return time.Time{}
	}
	return now.Add(time.Duration(secs) * time.Second)
}

func refuse(w http.ResponseWriter, r *http.Request, reason string, err error) {
	attrs := []any{"reason", reason}
	if err != nil {
		attrs = append(attrs, "error", err)
	}
	slog.WarnContext(r.Context(), "Sign-in refused", attrs...)
	http.Error(w, "sign-in failed", http.StatusBadRequest)
}
