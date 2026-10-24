package session

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fintrace-project/fintrace-bff/internal/config"
)

// Serves a discovery document; edit adjusts it per case, issuer defaulting to the server's own URL.
func newFakeIssuer(t *testing.T, edit func(doc map[string]any)) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	auth, err := NewOIDC(t.Context(), testConfig(t, srv.URL), &http.Client{Transport: transport})
	if err != nil {
		t.Fatalf("NewOIDC() error = %v", err)
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

			auth, err := NewOIDC(t.Context(), testConfig(t, issuer), http.DefaultClient)

			if err == nil {
				t.Fatalf("NewOIDC() = %+v, want an error", auth)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}
