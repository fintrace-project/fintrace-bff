package session

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	signoutTestID     = "session-id-1"
	testEndSessionURL = "https://idp.example/logout"
	testPostLogoutURL = "http://localhost:8100/"
	testStoredIDToken = "id-token-1"
	testStoredSubject = "user-1"
)

// Signing out needs only the realm's end-session URL, never a call to it.
func newSignoutAuth(t *testing.T) (*Auth, *fakeStore) {
	t.Helper()
	endSession, err := url.Parse(testEndSessionURL)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return signedIn }
	store := newFakeStore(clock)
	a := &Auth{
		oidc: &OIDC{
			OAuth2:                oauth2.Config{ClientID: "fintrace-bff"},
			EndSessionURL:         endSession,
			PostLogoutRedirectURL: testPostLogoutURL,
		},
		store:         store,
		sessionIdle:   testSessionIdle,
		sessionMaxAge: testSessionMax,
		now:           clock,
	}

	s := Session{Subject: testStoredSubject, IDToken: testStoredIDToken, CreatedAt: signedIn, LastSeen: signedIn}
	if err := store.Save(t.Context(), asStoreKey(signoutTestID), s, deadline(s, testSessionIdle, testSessionMax)); err != nil {
		t.Fatal(err)
	}
	return a, store
}

func signOut(t *testing.T, a *Auth, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/sign-out", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	a.SignOut(rec, req)
	return rec.Result()
}

// Checks a 303 to the realm's end-session endpoint and returns its query.
func wantEndSession(t *testing.T, resp *http.Response) url.Values {
	t.Helper()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if got := location.Scheme + "://" + location.Host + location.Path; got != testEndSessionURL {
		t.Errorf("redirected to %q, want the realm's end-session endpoint", got)
	}
	query := location.Query()
	for name, want := range map[string]string{
		"post_logout_redirect_uri": testPostLogoutURL,
		"client_id":                "fintrace-bff",
	} {
		if got := query.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	return query
}

func wantSessionCookieCleared(t *testing.T, resp *http.Response) {
	t.Helper()
	c := sessionCookieIn(resp)
	if c == nil {
		t.Fatal("the session cookie was not cleared")
	}
	if c.Value != "" || c.MaxAge >= 0 {
		t.Errorf("cookie = %+v, want an empty value and a negative Max-Age", c)
	}
	if !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" {
		t.Errorf("cookie = %+v, want Secure, HttpOnly, Path=/ and no Domain, or the browser ignores a __Host- cookie", c)
	}
}

func TestSignOutEndsTheSessionAndTheRealms(t *testing.T) {
	a, store := newSignoutAuth(t)

	resp := signOut(t, a, &http.Cookie{Name: sessionCookie, Value: signoutTestID})

	query := wantEndSession(t, resp)
	if got := query.Get("id_token_hint"); got != testStoredIDToken {
		t.Errorf("id_token_hint = %q, want the stored ID token", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
	if len(store.entries) != 0 {
		t.Errorf("%d sessions still stored, want none", len(store.entries))
	}
	wantSessionCookieCleared(t, resp)
}

func TestSignOutWithoutASessionStillEndsTheRealms(t *testing.T) {
	tests := []struct {
		name    string
		cookies []*http.Cookie
	}{
		{name: "no cookie"},
		{name: "an empty cookie", cookies: []*http.Cookie{{Name: sessionCookie, Value: ""}}},
		{name: "a session the store does not know", cookies: []*http.Cookie{{Name: sessionCookie, Value: "unknown-id"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, store := newSignoutAuth(t)

			resp := signOut(t, a, tt.cookies...)

			query := wantEndSession(t, resp)
			if query.Has("id_token_hint") {
				t.Errorf("id_token_hint = %q, want none without a session", query.Get("id_token_hint"))
			}
			if got := resp.Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want %q", got, "no-store")
			}
			if _, ok := store.entries[asStoreKey(signoutTestID)]; !ok {
				t.Error("another session was deleted")
			}
			wantSessionCookieCleared(t, resp)
		})
	}
}

func TestSignOutAnswers503WhenTheSessionCannotBeLoaded(t *testing.T) {
	a, store := newSignoutAuth(t)
	store.loadErr = errors.New("store unavailable")

	resp := signOut(t, a, &http.Cookie{Name: sessionCookie, Value: signoutTestID})

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	if body, _ := io.ReadAll(resp.Body); string(body) != "sign-out unavailable\n" {
		t.Errorf("body = %q, want the generic answer", body)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("Location = %q, want no redirect", loc)
	}
}

func TestSignOutEndsTheRealmsSessionEvenIfTheStoredOneCannotBeDeleted(t *testing.T) {
	a, store := newSignoutAuth(t)
	store.deleteErr = errors.New("store unavailable")

	resp := signOut(t, a, &http.Cookie{Name: sessionCookie, Value: signoutTestID})

	query := wantEndSession(t, resp)
	if got := query.Get("id_token_hint"); got != testStoredIDToken {
		t.Errorf("id_token_hint = %q, want the stored ID token", got)
	}
	wantSessionCookieCleared(t, resp)
}
