package session

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func newTestAuth() *Auth {
	return &Auth{oidc: &OIDC{OAuth2: oauth2.Config{
		ClientID:    "fintrace-bff",
		Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.example/auth", TokenURL: "https://idp.example/token"},
		RedirectURL: "http://localhost:8100/auth/callback",
		Scopes:      []string{"openid"},
	}}}
}

func login(t *testing.T, a *Auth) (*http.Response, *url.URL, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	a.Login(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/login", nil))
	resp := rec.Result()

	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].Name != loginCookie {
		t.Fatalf("cookies = %v, want only %s", cookies, loginCookie)
	}
	return resp, location, cookies[0]
}

func TestLoginRedirectsToTheRealmWithPKCE(t *testing.T) {
	resp, location, cookie := login(t, newTestAuth())

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := location.Scheme + "://" + location.Host + location.Path; got != "https://idp.example/auth" {
		t.Errorf("redirected to %q, want the realm's authorization endpoint", got)
	}

	query := location.Query()
	for name, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "fintrace-bff",
		"redirect_uri":          "http://localhost:8100/auth/callback",
		"scope":                 "openid",
		"code_challenge_method": "S256",
	} {
		if got := query.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 3 {
		t.Fatalf("cookie value has %d parts, want state.nonce.verifier", len(parts))
	}
	state, nonce, verifier := parts[0], parts[1], parts[2]
	if state == "" || query.Get("state") != state {
		t.Errorf("state = %q, cookie holds %q", query.Get("state"), state)
	}
	if nonce == "" || query.Get("nonce") != nonce {
		t.Errorf("nonce = %q, cookie holds %q", query.Get("nonce"), nonce)
	}
	sum := sha256.Sum256([]byte(verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); query.Get("code_challenge") != want {
		t.Errorf("code_challenge = %q, want S256 of the cookie's verifier %q", query.Get("code_challenge"), want)
	}
	if strings.Contains(location.String(), verifier) {
		t.Error("the PKCE verifier leaked into the redirect URL")
	}
}

func TestLoginCookieMeetsTheHostPrefixRules(t *testing.T) {
	_, _, cookie := login(t, newTestAuth())

	if !cookie.Secure || !cookie.HttpOnly {
		t.Errorf("Secure = %t, HttpOnly = %t, want both", cookie.Secure, cookie.HttpOnly)
	}
	if cookie.Path != "/" || cookie.Domain != "" {
		t.Errorf("Path = %q, Domain = %q, want / and none", cookie.Path, cookie.Domain)
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.MaxAge != 300 {
		t.Errorf("MaxAge = %d, want 300", cookie.MaxAge)
	}
}

func TestLoginIssuesFreshValuesEachTime(t *testing.T) {
	a := newTestAuth()
	_, _, first := login(t, a)
	_, _, second := login(t, a)

	firstParts, secondParts := strings.Split(first.Value, "."), strings.Split(second.Value, ".")
	for i, name := range []string{"state", "nonce", "verifier"} {
		if firstParts[i] == secondParts[i] {
			t.Errorf("%s repeated across logins: %q", name, firstParts[i])
		}
	}
}
