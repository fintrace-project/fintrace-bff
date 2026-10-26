package session

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/fintrace-project/fintrace-bff/internal/config"
)

const testKeyID = "test-key"

var issuerKey = sync.OnceValue(func() *rsa.PrivateKey { return newRSAKey() })

func newRSAKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

// Serves a discovery document and a JWKS holding issuerKey; edit adjusts the document per case,
// issuer defaulting to the server's own URL.
func newFakeIssuer(t *testing.T, edit func(doc map[string]any)) *httptest.Server {
	t.Helper()
	return newFakeRealm(t, edit, nil)
}

// A token endpoint answers /token, given the issuer's URL to sign ID tokens for.
type tokenEndpoint func(w http.ResponseWriter, r *http.Request, issuer string)

func newFakeRealm(t *testing.T, edit func(doc map[string]any), token tokenEndpoint) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" && token != nil {
			token(w, r, srv.URL)
			return
		}
		if r.URL.Path == "/certs" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &issuerKey().PublicKey, KeyID: testKeyID, Algorithm: string(jose.RS256), Use: "sig",
			}}})
			return
		}
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		doc := map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/auth",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/certs",
			"end_session_endpoint":                  srv.URL + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		if edit != nil {
			edit(doc)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testConfig(t *testing.T, issuer string) config.Config {
	t.Helper()
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		t.Fatal(err)
	}
	return config.Config{
		IssuerURI:    issuerURL,
		PublicOrigin: &url.URL{Scheme: "http", Host: "localhost:8100"},
		ClientID:     "fintrace-bff",
		ClientSecret: "test-secret",
		SessionIdle:  testSessionIdle,
		SessionMax:   testSessionMax,
	}
}

type countingTransport struct {
	calls atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return http.DefaultTransport.RoundTrip(r)
}

func TestNewOIDCBuildsSignInFromDiscovery(t *testing.T) {
	srv := newFakeIssuer(t, nil)
	transport := &countingTransport{}

	auth, err := newOIDC(t.Context(), testConfig(t, srv.URL), &http.Client{Transport: transport})
	if err != nil {
		t.Fatalf("newOIDC() error = %v", err)
	}

	if transport.calls.Load() == 0 {
		t.Error("discovery did not go through the client passed in")
	}
	checks := []struct{ name, got, want string }{
		{"AuthURL", auth.OAuth2.Endpoint.AuthURL, srv.URL + "/auth"},
		{"TokenURL", auth.OAuth2.Endpoint.TokenURL, srv.URL + "/token"},
		{"RedirectURL", auth.OAuth2.RedirectURL, "http://localhost:8100/auth/callback"},
		{"ClientID", auth.OAuth2.ClientID, "fintrace-bff"},
		{"Scopes", strings.Join(auth.OAuth2.Scopes, " "), "openid"},
		{"EndSessionURL", auth.EndSessionURL.String(), srv.URL + "/logout"},
		{"PostLogoutRedirectURL", auth.PostLogoutRedirectURL, "http://localhost:8100/"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if auth.Verifier == nil {
		t.Error("Verifier is nil")
	}
}

func TestNewOIDCRefusesAnUnusableProvider(t *testing.T) {
	tests := []struct {
		name    string
		edit    func(doc map[string]any)
		status  int
		wantErr string
	}{
		{name: "a document naming another issuer",
			edit:    func(doc map[string]any) { doc["issuer"] = "https://elsewhere.example/realms/other" },
			wantErr: "oidc discovery at"},
		{name: "no end_session_endpoint",
			edit:    func(doc map[string]any) { delete(doc, "end_session_endpoint") },
			wantErr: "end_session_endpoint"},
		{name: "a server error", status: http.StatusInternalServerError, wantErr: "oidc discovery at"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := newFakeIssuer(t, tt.edit).URL
			if tt.status != 0 {
				failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tt.status)
				}))
				t.Cleanup(failing.Close)
				issuer = failing.URL
			}

			auth, err := newOIDC(t.Context(), testConfig(t, issuer), http.DefaultClient)

			if err == nil {
				t.Fatalf("newOIDC() = %+v, want an error", auth)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func idTokenClaims(issuer string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":   issuer,
		"sub":   "user-1",
		"aud":   "fintrace-bff",
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"nonce": "nonce-1",
	}
}

func signToken(t *testing.T, alg jose.SignatureAlgorithm, key any, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", testKeyID))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// go-jose refuses to sign with "none", so this token is assembled by hand.
func unsignedToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc.EncodeToString(payload) + "."
}

func TestVerifierAcceptsAnIDTokenFromTheRealm(t *testing.T) {
	tests := []struct {
		name string
		edit func(claims map[string]any)
	}{
		{name: "aud the client alone"},
		{name: "aud a list holding the client",
			edit: func(claims map[string]any) { claims["aud"] = []string{"account", "fintrace-bff"} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newFakeIssuer(t, nil)
			transport := &countingTransport{}
			// Cancelled once startup is over, as main's context is not: key fetches must not depend on it.
			ctx, cancel := context.WithCancel(t.Context())
			auth, err := newOIDC(ctx, testConfig(t, srv.URL), &http.Client{Transport: transport})
			cancel()
			if err != nil {
				t.Fatalf("newOIDC() error = %v", err)
			}
			claims := idTokenClaims(srv.URL)
			if tt.edit != nil {
				tt.edit(claims)
			}
			discoveryCalls := transport.calls.Load()

			idToken, err := auth.Verifier.Verify(t.Context(), signToken(t, jose.RS256, issuerKey(), claims))

			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if idToken.Subject != "user-1" {
				t.Errorf("Subject = %q, want %q", idToken.Subject, "user-1")
			}
			// go-oidc only exposes the nonce; comparing it with the one sent is the callback's job.
			if idToken.Nonce != "nonce-1" {
				t.Errorf("Nonce = %q, want %q", idToken.Nonce, "nonce-1")
			}
			if transport.calls.Load() == discoveryCalls {
				t.Error("the JWKS was not fetched through the client passed in")
			}
		})
	}
}

func TestVerifierRefusesAnIDTokenItCannotTrust(t *testing.T) {
	otherKey := newRSAKey()
	tests := []struct {
		name    string
		token   func(t *testing.T, claims map[string]any) string
		edit    func(claims map[string]any)
		wantErr string
	}{
		{name: "aud without the client",
			edit:    func(claims map[string]any) { claims["aud"] = []string{"fintrace-core", "account"} },
			wantErr: "expected audience"},
		{name: "another issuer",
			edit:    func(claims map[string]any) { claims["iss"] = "https://elsewhere.example/realms/other" },
			wantErr: "issued by a different provider"},
		{name: "expired",
			edit:    func(claims map[string]any) { claims["exp"] = time.Now().Add(-time.Minute).Unix() },
			wantErr: "token is expired"},
		{name: "signed by a key the realm does not publish",
			token: func(t *testing.T, claims map[string]any) string {
				return signToken(t, jose.RS256, otherKey, claims)
			},
			wantErr: "failed to verify signature"},
		{name: "alg none",
			token:   unsignedToken,
			wantErr: "malformed jwt"},
		{name: "HS256 keyed with the realm's public key",
			token: func(t *testing.T, claims map[string]any) string {
				return signToken(t, jose.HS256, issuerKey().N.Bytes(), claims)
			},
			wantErr: "malformed jwt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newFakeIssuer(t, nil)
			auth, err := newOIDC(t.Context(), testConfig(t, srv.URL), http.DefaultClient)
			if err != nil {
				t.Fatalf("newOIDC() error = %v", err)
			}
			claims := idTokenClaims(srv.URL)
			if tt.edit != nil {
				tt.edit(claims)
			}
			token := tt.token
			if token == nil {
				token = func(t *testing.T, claims map[string]any) string {
					return signToken(t, jose.RS256, issuerKey(), claims)
				}
			}

			idToken, err := auth.Verifier.Verify(t.Context(), token(t, claims))

			if err == nil {
				t.Fatalf("Verify() = %+v, want an error", idToken)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}
