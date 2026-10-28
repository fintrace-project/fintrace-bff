package session

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fintrace-project/fintrace-bff/internal/config"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

type OIDC struct {
	Verifier              *oidc.IDTokenVerifier
	AccessVerifier        *oidc.IDTokenVerifier
	OAuth2                oauth2.Config
	EndSessionURL         *url.URL
	PostLogoutRedirectURL string
}

func newOIDC(ctx context.Context, cfg config.Config, client *http.Client) (*OIDC, error) {
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURI.String())
	if err != nil {
		return nil, fmt.Errorf("oidc discovery at %s: %w", cfg.IssuerURI, err)
	}
	slog.Info("OIDC provider discovered", "issuer", cfg.IssuerURI)

	var doc struct {
		EndSessionURL string   `json:"end_session_endpoint"`
		JwksURI       string   `json:"jwks_uri"`
		Algs          []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := provider.Claims(&doc); err != nil {
		return nil, fmt.Errorf("oidc discovery document: %w", err)
	}

	endSessionURL, err := url.Parse(doc.EndSessionURL)
	if err != nil || doc.EndSessionURL == "" || !endSessionURL.IsAbs() {
		return nil, fmt.Errorf("oidc discovery: no usable end_session_endpoint %q", doc.EndSessionURL)
	}

	if jwksURI, err := url.Parse(doc.JwksURI); err != nil || doc.JwksURI == "" || !jwksURI.IsAbs() {
		return nil, fmt.Errorf("oidc discovery: no usable jwks_uri %q", doc.JwksURI)
	}

	algsStr, algs := knownAlgs(doc.Algs)
	if len(algs) == 0 {
		return nil, fmt.Errorf("oidc discovery: no usable id_token_signing_alg_values_supported %q", doc.Algs)
	}

	ks, err := newKeySet(ctx, client, doc.JwksURI, algs, keyRefetchInterval, keyRefreshInterval)
	if err != nil {
		return nil, err
	}

	return &OIDC{
		Verifier: oidc.NewVerifier(cfg.IssuerURI.String(), ks, &oidc.Config{
			ClientID:             cfg.ClientID,
			SupportedSigningAlgs: algsStr,
		}),
		AccessVerifier: oidc.NewVerifier(cfg.IssuerURI.String(), ks, &oidc.Config{
			SkipClientIDCheck:    true,
			SupportedSigningAlgs: algsStr,
		}),
		OAuth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.PublicOrigin.JoinPath("/auth/callback").String(),
			Scopes:       []string{oidc.ScopeOpenID},
		},
		EndSessionURL:         endSessionURL,
		PostLogoutRedirectURL: cfg.PublicOrigin.JoinPath("/").String(),
	}, nil
}

func knownAlgs(advertised []string) ([]string, []jose.SignatureAlgorithm) {
	var allKnownAlgs = []string{
		oidc.RS256, oidc.RS384, oidc.RS512,
		oidc.ES256, oidc.ES384, oidc.ES512,
		oidc.PS256, oidc.PS384, oidc.PS512,
		oidc.EdDSA,
	}

	var names []string
	var algs []jose.SignatureAlgorithm
	for _, name := range advertised {
		if slices.Contains(allKnownAlgs, name) {
			names = append(names, name)
			algs = append(algs, jose.SignatureAlgorithm(name))
		}
	}
	return names, algs
}
