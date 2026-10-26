package session

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	testSessionIdle = 7 * 24 * time.Hour
	testSessionMax  = 30 * 24 * time.Hour
)

var signedIn = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func storeOf(a *Auth) *fakeStore {
	return a.store.(*fakeStore)
}

func sessionCookieIn(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	return nil
}

// Signs in through the fake realm with the clock stopped at signedIn.
func signIn(t *testing.T, stub *tokenStub, more ...*http.Cookie) (*Auth, *http.Response) {
	t.Helper()
	a, cookie, scv := startSignIn(t, stub)
	a.now = func() time.Time { return signedIn }
	return a, callback(t, a, cookie, url.Values{"state": {scv.state}, "code": {"code-1"}}, more...)
}

func TestCallbackIssuesASessionCookie(t *testing.T) {
	_, resp := signIn(t, &tokenStub{})

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}
	c := sessionCookieIn(resp)
	if c == nil {
		t.Fatal("no session cookie set")
	}
	if c.Value == "" {
		t.Error("the session cookie is empty")
	}
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
		t.Errorf("cookie = %+v, want Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain, as __Host- requires", c)
	}
	if want := int(testSessionMax.Seconds()); c.MaxAge != want {
		t.Errorf("Max-Age = %d, want %d, the session's maximum", c.MaxAge, want)
	}
}

func TestCallbackStoresTheSessionUnderTheHashOfItsID(t *testing.T) {
	a, resp := signIn(t, &tokenStub{refreshExpiresIn: 3600})
	c := sessionCookieIn(resp)
	if c == nil {
		t.Fatal("no session cookie set")
	}
	f := storeOf(a)

	if len(f.entries) != 1 {
		t.Fatalf("%d sessions stored, want 1", len(f.entries))
	}
	if _, raw := f.entries[StoreKey(c.Value)]; raw {
		t.Error("the session is stored under the cookie's raw value")
	}
	e, ok := f.entries[asStoreKey(c.Value)]
	if !ok {
		t.Fatal("no session stored under the hash of the cookie's value")
	}

	s := e.session
	if s.Subject != "user-1" || s.AccessToken != "access-1" || s.RefreshToken != "refresh-1" {
		t.Errorf("session = %+v, want the realm's subject and tokens", s)
	}
	if s.IDToken == "" {
		t.Error("the raw ID token was not kept, and sign-out needs it")
	}
	if s.AccessExpiry.IsZero() {
		t.Error("no access token expiry")
	}
	if !s.CreatedAt.Equal(signedIn) || !s.LastSeen.Equal(signedIn) {
		t.Errorf("CreatedAt = %v, LastSeen = %v, want both %v", s.CreatedAt, s.LastSeen, signedIn)
	}
	if want := signedIn.Add(time.Hour); !s.RefreshExpiry.Equal(want) {
		t.Errorf("RefreshExpiry = %v, want %v from refresh_expires_in", s.RefreshExpiry, want)
	}
	// The refresh token's hour is the earliest of the three limits
	if want := signedIn.Add(time.Hour); !e.expiresAt.Equal(want) {
		t.Errorf("saved until %v, want %v", e.expiresAt, want)
	}
}

func TestCallbackWithoutARefreshExpiryUsesTheBFFsLimits(t *testing.T) {
	a, resp := signIn(t, &tokenStub{})
	c := sessionCookieIn(resp)
	if c == nil {
		t.Fatal("no session cookie set")
	}
	e := storeOf(a).entries[asStoreKey(c.Value)]

	if !e.session.RefreshExpiry.IsZero() {
		t.Errorf("RefreshExpiry = %v, want none without refresh_expires_in", e.session.RefreshExpiry)
	}
	if want := signedIn.Add(testSessionIdle); !e.expiresAt.Equal(want) {
		t.Errorf("saved until %v, want %v, the idle limit", e.expiresAt, want)
	}
}

func TestCallbackReplacesAnEarlierSession(t *testing.T) {
	stub := &tokenStub{}
	a, cookie, scv := startSignIn(t, stub)
	f := storeOf(a)
	const oldID = "old-session-id"
	if err := f.Save(t.Context(), asStoreKey(oldID), Session{Subject: "user-1"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	resp := callback(t, a, cookie, url.Values{"state": {scv.state}, "code": {"code-1"}},
		&http.Cookie{Name: sessionCookie, Value: oldID})

	if _, ok := f.entries[asStoreKey(oldID)]; ok {
		t.Error("the earlier session is still stored")
	}
	c := sessionCookieIn(resp)
	if c == nil || c.Value == oldID {
		t.Fatalf("session cookie = %+v, want a new id", c)
	}
	if _, ok := f.entries[asStoreKey(c.Value)]; !ok {
		t.Error("the new session is not stored")
	}
}

func TestCallbackSignsInEvenIfTheEarlierSessionCannotBeDeleted(t *testing.T) {
	stub := &tokenStub{}
	a, cookie, scv := startSignIn(t, stub)
	f := storeOf(a)
	f.deleteErr = errors.New("store unavailable")

	resp := callback(t, a, cookie, url.Values{"state": {scv.state}, "code": {"code-1"}},
		&http.Cookie{Name: sessionCookie, Value: "old-session-id"})

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}
	if sessionCookieIn(resp) == nil || len(f.entries) != 1 {
		t.Errorf("no new session issued: %d stored", len(f.entries))
	}
}

func TestCallbackAnswers503WhenTheSessionCannotBeSaved(t *testing.T) {
	stub := &tokenStub{}
	a, cookie, scv := startSignIn(t, stub)
	storeOf(a).saveErr = errors.New("store unavailable")

	resp := callback(t, a, cookie, url.Values{"state": {scv.state}, "code": {"code-1"}})

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	if body, _ := io.ReadAll(resp.Body); string(body) != "sign-in unavailable\n" {
		t.Errorf("body = %q, want the generic answer", body)
	}
	if c := sessionCookieIn(resp); c != nil {
		t.Errorf("a session cookie was set for a session that was not saved: %+v", c)
	}
	if !signInCookieCleared(resp) {
		t.Error("the sign-in cookie was not cleared")
	}
}

func TestRefreshExpiry(t *testing.T) {
	tests := []struct {
		name  string
		extra map[string]any
		want  time.Time
	}{
		{name: "an hour", extra: map[string]any{"refresh_expires_in": float64(3600)}, want: signedIn.Add(time.Hour)},
		{name: "Remember me's seven days", extra: map[string]any{"refresh_expires_in": float64(604800)},
			want: signedIn.Add(7 * 24 * time.Hour)},
		{name: "zero, an offline token, is no limit", extra: map[string]any{"refresh_expires_in": float64(0)}},
		{name: "negative is no limit", extra: map[string]any{"refresh_expires_in": float64(-1)}},
		{name: "absent is no limit", extra: map[string]any{}},
		{name: "a string is not a number", extra: map[string]any{"refresh_expires_in": "3600"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := (&oauth2.Token{}).WithExtra(tt.extra)
			if got := refreshExpiry(token, signedIn); !got.Equal(tt.want) {
				t.Errorf("refreshExpiry() = %v, want %v", got, tt.want)
			}
		})
	}
}
