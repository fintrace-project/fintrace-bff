package session

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// Answers the code exchange the way Keycloak does, recording what the BFF sent.
type tokenStub struct {
	t           *testing.T
	nonce       string
	key         any
	invalid     bool
	omitIDToken bool

	mu    sync.Mutex
	calls int
	form  url.Values
	user  string
	pass  string
}

func (s *tokenStub) serve(w http.ResponseWriter, r *http.Request, issuer string) {
	if err := r.ParseForm(); err != nil {
		s.t.Errorf("token request form: %v", err)
	}
	user, pass, _ := r.BasicAuth()
	s.mu.Lock()
	s.calls++
	s.form, s.user, s.pass = r.PostForm, user, pass
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if s.invalid {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"Code not valid"}`)
		return
	}
	body := map[string]any{"access_token": "access-1", "token_type": "Bearer", "expires_in": 300}
	if !s.omitIDToken {
		claims := idTokenClaims(issuer)
		claims["nonce"] = s.nonce
		key := s.key
		if key == nil {
			key = issuerKey()
		}
		body["id_token"] = signToken(s.t, jose.RS256, key, claims)
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (s *tokenStub) recorded() (calls int, form url.Values, user, pass string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.form, s.user, s.pass
}

// Starts a real login against a fake realm, so the callback sees the cookie and state Login issued.
func startLogin(t *testing.T, stub *tokenStub) (*Auth, *http.Cookie, loginCookieValue) {
	t.Helper()
	stub.t = t
	srv := newFakeRealm(t, nil, stub.serve)
	a, err := NewAuth(t.Context(), testConfig(t, srv.URL), http.DefaultClient)
	if err != nil {
		t.Fatalf("NewAuth() error = %v", err)
	}
	_, _, cookie := login(t, a)
	lcv, err := parseLoginCookie(cookie)
	if err != nil {
		t.Fatalf("Login's own cookie does not parse: %v", err)
	}
	if stub.nonce == "" {
		stub.nonce = lcv.nonce
	}
	return a, cookie, lcv
}

func callback(t *testing.T, a *Auth, cookie *http.Cookie, query url.Values) *http.Response {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/callback?"+query.Encode(), nil)
	if cookie != nil {
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	rec := httptest.NewRecorder()
	a.Callback(rec, req)
	return rec.Result()
}

func loginCookieCleared(resp *http.Response) bool {
	for _, c := range resp.Cookies() {
		if c.Name == loginCookie && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestCallbackExchangesTheCodeAndSignsIn(t *testing.T) {
	stub := &tokenStub{}
	a, cookie, lcv := startLogin(t, stub)

	resp := callback(t, a, cookie, url.Values{"state": {lcv.state}, "code": {"code-1"}})

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}
	if got := resp.Header.Get("Location"); got != "/" {
		t.Errorf("Location = %q, want /", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if !loginCookieCleared(resp) {
		t.Error("the login cookie was not cleared")
	}

	calls, form, user, pass := stub.recorded()
	if calls != 1 {
		t.Fatalf("token endpoint called %d times, want 1", calls)
	}
	for name, want := range map[string]string{
		"grant_type":    "authorization_code",
		"code":          "code-1",
		"code_verifier": lcv.verifier,
		"redirect_uri":  "http://localhost:8100/auth/callback",
	} {
		if got := form.Get(name); got != want {
			t.Errorf("token request %s = %q, want %q", name, got, want)
		}
	}
	if user != "fintrace-bff" || pass != "test-secret" {
		t.Errorf("client authenticated as %q / %q, want fintrace-bff / test-secret", user, pass)
	}
}

func TestCallbackRefusesWhatItCannotTrust(t *testing.T) {
	const (
		rightState = "<issued>" // replaced by the state Login issued
		wrongState = "not-the-state"
	)
	tests := []struct {
		name         string
		stub         *tokenStub
		cookie       func(c *http.Cookie) *http.Cookie
		query        url.Values
		wantExchange bool
	}{
		{name: "no login cookie",
			cookie: func(*http.Cookie) *http.Cookie { return nil },
			query:  url.Values{"state": {rightState}, "code": {"code-1"}}},
		{name: "a malformed login cookie",
			cookie: func(c *http.Cookie) *http.Cookie { return &http.Cookie{Name: c.Name, Value: "only.two"} },
			query:  url.Values{"state": {rightState}, "code": {"code-1"}}},
		{name: "another state",
			query: url.Values{"state": {wrongState}, "code": {"code-1"}}},
		{name: "no state",
			query: url.Values{"code": {"code-1"}}},
		{name: "the realm's error",
			query: url.Values{"state": {rightState}, "error": {"access_denied"}}},
		{name: "an error under another state",
			query: url.Values{"state": {wrongState}, "error": {"access_denied"}}},
		{name: "no code",
			query: url.Values{"state": {rightState}}},
		{name: "a code the realm refuses",
			stub:         &tokenStub{invalid: true},
			query:        url.Values{"state": {rightState}, "code": {"code-1"}},
			wantExchange: true},
		{name: "no ID token in the answer",
			stub:         &tokenStub{omitIDToken: true},
			query:        url.Values{"state": {rightState}, "code": {"code-1"}},
			wantExchange: true},
		{name: "an ID token for another nonce",
			stub:         &tokenStub{nonce: "another-nonce"},
			query:        url.Values{"state": {rightState}, "code": {"code-1"}},
			wantExchange: true},
		{name: "an ID token signed by a key the realm does not publish",
			stub:         &tokenStub{key: newRSAKey()},
			query:        url.Values{"state": {rightState}, "code": {"code-1"}},
			wantExchange: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := tt.stub
			if stub == nil {
				stub = &tokenStub{}
			}
			a, cookie, lcv := startLogin(t, stub)
			if tt.cookie != nil {
				cookie = tt.cookie(cookie)
			}
			if tt.query.Get("state") == rightState {
				tt.query.Set("state", lcv.state)
			}

			resp := callback(t, a, cookie, tt.query)

			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
			}
			if body, _ := io.ReadAll(resp.Body); string(body) != "sign-in failed\n" {
				t.Errorf("body = %q, want the generic refusal", body)
			}
			if resp.Header.Get("Location") != "" {
				t.Error("a refusal redirected")
			}
			if !loginCookieCleared(resp) {
				t.Error("the login cookie was not cleared")
			}
			if calls, _, _, _ := stub.recorded(); (calls > 0) != tt.wantExchange {
				t.Errorf("token endpoint called %d times, want an exchange: %t", calls, tt.wantExchange)
			}
		})
	}
}
