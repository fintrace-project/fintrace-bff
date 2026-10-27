package session

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/fintrace-project/fintrace-bff/internal/httperr"
)

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantToken string
		wantOK    bool
	}{
		{name: "Bearer", header: "Bearer abc", wantToken: "abc", wantOK: true},
		{name: "lower case", header: "bearer abc", wantToken: "abc", wantOK: true},
		{name: "upper case", header: "BEARER abc", wantToken: "abc", wantOK: true},
		{name: "two spaces", header: "Bearer  abc", wantToken: "abc", wantOK: true},
		{name: "the scheme alone", header: "Bearer", wantOK: true},
		{name: "Basic", header: "Basic dXNlcjpwYXNz"},
		{name: "no space after the scheme", header: "Bearerabc"},
		{name: "empty", header: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/workspaces", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			token, ok := BearerToken(req)

			if token != tt.wantToken || ok != tt.wantOK {
				t.Errorf("BearerToken() = %q, %t; want %q, %t", token, ok, tt.wantToken, tt.wantOK)
			}
		})
	}
}

// Shaped like fintrace-test's client-credentials token: aud names Core, never the BFF.
func accessTokenClaims(issuer string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": issuer,
		"sub": "service-account-1",
		"azp": "fintrace-test",
		"aud": []string{"fintrace-core", "account"},
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
}

func newBearerAuth(t *testing.T) (*Auth, string) {
	t.Helper()
	srv := newFakeIssuer(t, nil)
	o, err := newOIDC(t.Context(), testConfig(t, srv.URL), http.DefaultClient)
	if err != nil {
		t.Fatalf("newOIDC() error = %v", err)
	}
	return &Auth{oidc: o}, srv.URL
}

func verifyBearer(a *Auth, req *http.Request) (*httptest.ResponseRecorder, *nextRecorder) {
	next := &nextRecorder{}
	rec := httptest.NewRecorder()
	a.VerifyBearer(next).ServeHTTP(rec, req)
	return rec, next
}

func bearerRequest(t *testing.T, authorization ...string) *http.Request {
	t.Helper()
	req := apiRequest(t)
	for _, v := range authorization {
		req.Header.Add("Authorization", v)
	}
	return req
}

func TestVerifyBearerForwardsATokenTheRealmSigned(t *testing.T) {
	tests := []struct {
		name string
		edit func(claims map[string]any)
	}{
		{name: "aud naming Core"},
		// The audience is the upstream's to check, so the BFF must not refuse a token not meant for it.
		{name: "aud naming another client alone",
			edit: func(claims map[string]any) { claims["aud"] = "fintrace-mok-importer" }},
		{name: "no aud", edit: func(claims map[string]any) { delete(claims, "aud") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, issuer := newBearerAuth(t)
			claims := accessTokenClaims(issuer)
			if tt.edit != nil {
				tt.edit(claims)
			}
			token := signToken(t, jose.RS256, issuerKey(), claims)

			rec, next := verifyBearer(a, bearerRequest(t, "Bearer "+token))

			if !next.called {
				t.Fatalf("next not called, status = %d, body %q", rec.Code, rec.Body.String())
			}
			if got := next.req.Header.Get("Authorization"); got != "Bearer "+token {
				t.Errorf("Authorization = %q, want the caller's token", got)
			}
		})
	}
}

func TestVerifyBearerForwardsExactlyTheTokenItVerified(t *testing.T) {
	a, issuer := newBearerAuth(t)
	token := signToken(t, jose.RS256, issuerKey(), accessTokenClaims(issuer))
	req := bearerRequest(t, "bearer  "+token, "Bearer another-token")

	rec, next := verifyBearer(a, req)

	if !next.called {
		t.Fatalf("next not called, status = %d", rec.Code)
	}
	want := []string{"Bearer " + token}
	if got := next.req.Header.Values("Authorization"); !slices.Equal(got, want) {
		t.Errorf("Authorization = %q, want only the verified token in standard form", got)
	}
	if got := req.Header.Values("Authorization"); len(got) != 2 {
		t.Errorf("the incoming request's Authorization = %q, want it left unchanged", got)
	}
}

func TestVerifyBearerRefusesATokenItCannotTrust(t *testing.T) {
	otherKey := newRSAKey()
	tests := []struct {
		name   string
		header func(t *testing.T, issuer string) string
	}{
		{name: "expired", header: func(t *testing.T, issuer string) string {
			claims := accessTokenClaims(issuer)
			claims["exp"] = time.Now().Add(-time.Minute).Unix()
			return "Bearer " + signToken(t, jose.RS256, issuerKey(), claims)
		}},
		{name: "another issuer", header: func(t *testing.T, issuer string) string {
			return "Bearer " + signToken(t, jose.RS256, issuerKey(), accessTokenClaims("https://elsewhere.example/realms/other"))
		}},
		{name: "signed by a key the realm does not publish", header: func(t *testing.T, issuer string) string {
			return "Bearer " + signToken(t, jose.RS256, otherKey, accessTokenClaims(issuer))
		}},
		{name: "alg none", header: func(t *testing.T, issuer string) string {
			return "Bearer " + unsignedToken(t, accessTokenClaims(issuer))
		}},
		{name: "HS256 keyed with the realm's public key", header: func(t *testing.T, issuer string) string {
			return "Bearer " + signToken(t, jose.HS256, issuerKey().N.Bytes(), accessTokenClaims(issuer))
		}},
		{name: "not a JWT", header: func(*testing.T, string) string { return "Bearer not-a-jwt" }},
		{name: "the scheme alone", header: func(*testing.T, string) string { return "Bearer" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, issuer := newBearerAuth(t)

			rec, next := verifyBearer(a, bearerRequest(t, tt.header(t, issuer)))

			wantHTTPError(t, rec, http.StatusUnauthorized, httperr.InvalidToken)
			if got, want := rec.Header().Get("WWW-Authenticate"), `Bearer error="invalid_token"`; got != want {
				t.Errorf("WWW-Authenticate = %q, want %q", got, want)
			}
			if next.called {
				t.Error("next was called with a token the BFF cannot trust")
			}
		})
	}
}
