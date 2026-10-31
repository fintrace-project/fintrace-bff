package session

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/httperr"
)

func sessionState(t *testing.T, a *Auth, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/session", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	a.SessionState(rec, req)
	return rec
}

func wantNoStore(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func saveOwn(t *testing.T, f *loadFixture, s Session) {
	t.Helper()
	if err := f.store.Save(t.Context(), asStoreKey(loadTestID), s, deadline(s, testSessionIdle, testSessionMax)); err != nil {
		t.Fatal(err)
	}
}

func TestSessionStateRefusesWithoutASession(t *testing.T) {
	tests := []struct {
		name    string
		cookies []*http.Cookie
		later   time.Duration
	}{
		{name: "no cookie"},
		{name: "an empty cookie", cookies: []*http.Cookie{{Name: sessionCookie, Value: ""}}},
		{name: "an id the store does not know", cookies: []*http.Cookie{{Name: sessionCookie, Value: "unknown"}}},
		{name: "only the sign-in cookie", cookies: []*http.Cookie{{Name: signInCookie, Value: loadTestID}}},
		{name: "a session past its deadline", cookies: []*http.Cookie{ownCookie()}, later: testSessionIdle},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newLoadFixture(t)
			f.now = f.now.Add(tt.later)

			rec := sessionState(t, f.a, tt.cookies...)

			wantHTTPError(t, rec, http.StatusUnauthorized, httperr.NoSession)
			wantNoStore(t, rec)
		})
	}
}

func TestSessionStateAnswers503WhenTheStoreFails(t *testing.T) {
	f := newLoadFixture(t)
	f.store.loadErr = errors.New("store down")

	rec := sessionState(t, f.a, ownCookie())

	wantHTTPError(t, rec, http.StatusServiceUnavailable, httperr.SessionUnavailable)
	wantNoStore(t, rec)
}

func TestSessionStateAnswersTheUserAndTheDeadline(t *testing.T) {
	tests := []struct {
		name    string
		created time.Time
		want    time.Time
	}{
		{name: "the idle limit decides", created: signedIn,
			want: signedIn.Add(testSessionIdle)},
		{name: "the maximum decides", created: signedIn.Add(-testSessionMax + 24*time.Hour),
			want: signedIn.Add(24 * time.Hour)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newLoadFixture(t)
			saveOwn(t, f, Session{UserID: "user-id-1", Subject: "user-1", AccessToken: "access-1",
				AccessExpiry: signedIn.Add(time.Hour), CreatedAt: tt.created, LastSeen: signedIn})

			rec := sessionState(t, f.a, ownCookie())

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body %q", rec.Code, http.StatusOK, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			wantNoStore(t, rec)

			// Decoded loosely, so a renamed or extra field fails rather than reading as empty
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body %q is not JSON: %v", rec.Body.String(), err)
			}
			if len(body) != 2 {
				t.Errorf("body = %v, want exactly userId and expiresAt", body)
			}
			if body["userId"] != "user-id-1" {
				t.Errorf("userId = %v, want user-id-1", body["userId"])
			}
			raw, _ := body["expiresAt"].(string)
			expiresAt, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				t.Fatalf("expiresAt = %q, want RFC 3339: %v", raw, err)
			}
			if !expiresAt.Equal(tt.want) {
				t.Errorf("expiresAt = %v, want %v", expiresAt, tt.want)
			}
			if expiresAt.Location() != time.UTC {
				t.Errorf("expiresAt = %q, want UTC", raw)
			}
		})
	}
}

// The rule the endpoint exists under (§7.4): a shell polling it must not keep an idle session alive.
func TestSessionStateNeverTouchesTheSession(t *testing.T) {
	f := newRefreshFixture(t, &refreshRealm{})
	before, _ := f.stored(t)
	// Past the touch interval and inside the refresh lag, so a load would both refresh and save
	f.now = accessExpiry

	rec := sessionState(t, f.a, ownCookie())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %q", rec.Code, http.StatusOK, rec.Body.String())
	}
	after, ok := f.stored(t)
	if !ok {
		t.Fatal("the session is no longer stored")
	}
	if after != before {
		t.Errorf("stored = %+v, want it untouched: %+v", after, before)
	}
	if n := f.calls(); n != 0 {
		t.Errorf("%d token calls to the realm, want none", n)
	}
}
