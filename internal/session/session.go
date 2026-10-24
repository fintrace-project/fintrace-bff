package session

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

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
	oidc *OIDC
}

func NewAuth(ctx context.Context, cfg config.Config, client *http.Client) (*Auth, error) {
	o, err := newOIDC(ctx, cfg, client)
	if err != nil {
		return nil, err
	}
	return &Auth{oidc: o}, nil
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	state := rand.Text()
	nonce := rand.Text()
	verifier := oauth2.GenerateVerifier()

	http.SetCookie(w, &http.Cookie{
		Name:     loginCookie,
		Secure:   true,
		Path:     "/",
		Domain:   "",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
		Value:    state + "." + nonce + "." + verifier,
	})

	loginURL := a.oidc.OAuth2.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	w.Header().Set("Cache-Control", "no-store")

	http.Redirect(w, r, loginURL, http.StatusFound)
}
