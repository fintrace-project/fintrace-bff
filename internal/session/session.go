package session

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/fintrace-project/fintrace-bff/internal/config"
)

type OIDC struct {
	Verifier      *oidc.IDTokenVerifier
	OAuth2        oauth2.Config
	EndSessionURL *url.URL
}

func NewOIDC(ctx context.Context, cfg config.Config, client *http.Client) (*OIDC, error) {
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
