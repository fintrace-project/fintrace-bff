package session

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/fintrace-project/fintrace-bff/internal/config"
)

const loginCookie = "__Host-fintrace-login"

type OIDC struct {
	Verifier      *oidc.IDTokenVerifier
	OAuth2        oauth2.Config
	EndSessionURL *url.URL
}

func newOIDC(ctx context.Context, cfg config.Config, client *http.Client) (*OIDC, error) {
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURI.String())
	if err != nil {
		return nil, fmt.Errorf("oidc discovery at %s: %w", cfg.IssuerURI, err)
	}
	slog.Info("OIDC provider discovered", "issuer", cfg.IssuerURI)

	var doc struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&doc); err != nil {
		return nil, fmt.Errorf("oidc discovery document: %w", err)
	}

	endSession, err := url.Parse(doc.EndSession)
	if err != nil || doc.EndSession == "" || !endSession.IsAbs() {
		return nil, fmt.Errorf("oidc discovery: no usable end_session_endpoint %q", doc.EndSession)
	}

	return &OIDC{
		Verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		OAuth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.PublicOrigin.JoinPath("/auth/callback").String(),
			Scopes:       []string{oidc.ScopeOpenID},
		},
		EndSessionURL: endSession,
	}, nil
}

type Auth struct {
	oidc   *OIDC
	client *http.Client
}

func NewAuth(ctx context.Context, cfg config.Config, client *http.Client) (*Auth, error) {
	o, err := newOIDC(ctx, cfg, client)
	if err != nil {
		return nil, err
	}
	return &Auth{oidc: o, client: client}, nil
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	lcv := newLoginCookieValue()

	http.SetCookie(w, configureLoginCookie(lcv.cookieValue(), 300))

	loginURL := a.oidc.OAuth2.AuthCodeURL(lcv.state, oidc.Nonce(lcv.nonce), oauth2.S256ChallengeOption(lcv.verifier))
	w.Header().Set("Cache-Control", "no-store")

	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (a *Auth) Callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(loginCookie)
	http.SetCookie(w, configureLoginCookie("", -1)) // Clean login cookie explicitly
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

	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		refuse(w, r, "Token response carries no ID token", nil)
		return
	}
	idToken, err := a.oidc.Verifier.Verify(ctx, raw)
	if err != nil {
		refuse(w, r, "Sign-in ID token rejected", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(lcv.nonce)) != 1 {
		refuse(w, r, "Sign-in nonce does not match", nil)
		return
	}

	a.completeLogin(w, r, idToken)
}

func (a *Auth) completeLogin(w http.ResponseWriter, r *http.Request, idToken *oidc.IDToken) {
	slog.InfoContext(r.Context(), "Signed in", "sub", idToken.Subject)
	w.Header().Set("Cache-Control", "no-store")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type loginCookieValue struct {
	state, nonce, verifier string
}

func newLoginCookieValue() loginCookieValue {
	return loginCookieValue{
		state:    rand.Text(),
		nonce:    rand.Text(),
		verifier: oauth2.GenerateVerifier(),
	}
}

func (f loginCookieValue) cookieValue() string {
	return f.state + "." + f.nonce + "." + f.verifier
}

func parseLoginCookie(cookie *http.Cookie) (loginCookieValue, error) {
	parts := strings.Split(cookie.Value, ".")

	if len(parts) != 3 ||
		parts[0] == "" ||
		parts[1] == "" ||
		parts[2] == "" {
		return loginCookieValue{}, errors.New("cookie value has wrong format")
	}

	return loginCookieValue{state: parts[0], nonce: parts[1], verifier: parts[2]}, nil
}

func configureLoginCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     loginCookie,
		Secure:   true,
		Path:     "/",
		Domain:   "",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
		Value:    value,
	}
}

func refuse(w http.ResponseWriter, r *http.Request, reason string, err error) {
	attrs := []any{"reason", reason}
	if err != nil {
		attrs = append(attrs, "error", err)
	}
	slog.WarnContext(r.Context(), "Sign-in refused", attrs...)
	http.Error(w, "sign-in failed", http.StatusBadRequest)
}
