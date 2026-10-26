package session

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const loadTestID = "session-id-1"

type loadFixture struct {
	a     *Auth
	store *fakeStore
	now   time.Time
}

// An Auth whose store and own clock read the same time, so moving f.now moves both.
// load needs no realm, so the OIDC half is left out.
func newLoadFixture(t *testing.T) *loadFixture {
	t.Helper()
	f := &loadFixture{now: signedIn}
	clock := func() time.Time { return f.now }
	f.store = newFakeStore(clock)
	f.a = &Auth{store: f.store, sessionIdle: testSessionIdle, sessionMaxAge: testSessionMax, now: clock}

	s := Session{Subject: "user-1", AccessToken: "access-1", CreatedAt: signedIn, LastSeen: signedIn}
	if err := f.store.Save(t.Context(), asStoreKey(loadTestID), s, deadline(s, testSessionIdle, testSessionMax)); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *loadFixture) load(t *testing.T, cookies ...*http.Cookie) (Session, StoreKey, error) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/anything", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return f.a.load(req)
}

func (f *loadFixture) loadOwn(t *testing.T) (Session, StoreKey, error) {
	t.Helper()
	return f.load(t, &http.Cookie{Name: sessionCookie, Value: loadTestID})
}

func (f *loadFixture) stored(t *testing.T) fakeEntry {
	t.Helper()
	e, ok := f.store.entries[asStoreKey(loadTestID)]
	if !ok {
		t.Fatal("the session is no longer stored")
	}
	return e
}

func wantNoSession(t *testing.T, s Session, key StoreKey, err error) {
	t.Helper()
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("load() error = %v, want ErrNoSession", err)
	}
	if s != (Session{}) || key != "" {
		t.Errorf("load() = %+v, %q alongside ErrNoSession, want zero values", s, key)
	}
}

func TestLoadWithoutASessionCookie(t *testing.T) {
	tests := []struct {
		name    string
		cookies []*http.Cookie
	}{
		{name: "no cookie"},
		{name: "an empty cookie", cookies: []*http.Cookie{{Name: sessionCookie, Value: ""}}},
		{name: "only the sign-in cookie", cookies: []*http.Cookie{{Name: signInCookie, Value: loadTestID}}},
		{name: "an id the store does not know", cookies: []*http.Cookie{{Name: sessionCookie, Value: "unknown"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newLoadFixture(t)
			s, key, err := f.load(t, tt.cookies...)
			wantNoSession(t, s, key, err)
		})
	}
}

func TestLoadReturnsTheSessionAndExtendsItsIdleDeadline(t *testing.T) {
	f := newLoadFixture(t)
	f.now = signedIn.Add(2 * time.Hour)

	s, key, err := f.loadOwn(t)

	if err != nil {
		t.Fatalf("load() error = %v", err)
	}
	if key != asStoreKey(loadTestID) {
		t.Errorf("key = %q, want the hash of the cookie's id", key)
	}
	if s.Subject != "user-1" || s.AccessToken != "access-1" {
		t.Errorf("session = %+v, want the stored one", s)
	}
	if !s.LastSeen.Equal(f.now) || !s.CreatedAt.Equal(signedIn) {
		t.Errorf("LastSeen = %v, CreatedAt = %v; want %v and the unchanged %v", s.LastSeen, s.CreatedAt, f.now, signedIn)
	}
	e := f.stored(t)
	if !e.session.LastSeen.Equal(f.now) {
		t.Errorf("stored LastSeen = %v, want %v", e.session.LastSeen, f.now)
	}
	if want := f.now.Add(testSessionIdle); !e.expiresAt.Equal(want) {
		t.Errorf("stored until %v, want %v, the idle limit from now", e.expiresAt, want)
	}
}

func TestLoadTouchesAtMostOnceAMinute(t *testing.T) {
	tests := []struct {
		name    string
		since   time.Duration
		touched bool
	}{
		{name: "59 seconds after the last touch", since: 59 * time.Second},
		{name: "a minute after the last touch", since: time.Minute, touched: true},
		{name: "61 seconds after the last touch", since: 61 * time.Second, touched: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newLoadFixture(t)
			f.now = signedIn.Add(tt.since)

			if _, _, err := f.loadOwn(t); err != nil {
				t.Fatalf("load() error = %v", err)
			}

			want := signedIn.Add(testSessionIdle)
			if tt.touched {
				want = f.now.Add(testSessionIdle)
			}
			if got := f.stored(t).expiresAt; !got.Equal(want) {
				t.Errorf("stored until %v, want %v (touched: %t)", got, want, tt.touched)
			}
		})
	}
}

func TestLoadEndsAnIdleSession(t *testing.T) {
	f := newLoadFixture(t)

	f.now = signedIn.Add(testSessionIdle - time.Nanosecond)
	if _, _, err := f.loadOwn(t); err != nil {
		t.Fatalf("load() just before the idle deadline error = %v", err)
	}

	f = newLoadFixture(t)
	f.now = signedIn.Add(testSessionIdle)
	s, key, err := f.loadOwn(t)
	wantNoSession(t, s, key, err)
}

func TestLoadEndsASessionAtItsMaximumHoweverActive(t *testing.T) {
	f := newLoadFixture(t)

	// Used every six days, so it never goes idle, until thirty days after sign-in
	for day := 6; day < 30; day += 6 {
		f.now = signedIn.Add(time.Duration(day) * 24 * time.Hour)
		if _, _, err := f.loadOwn(t); err != nil {
			t.Fatalf("load() on day %d error = %v", day, err)
		}
	}

	f.now = signedIn.Add(testSessionMax)
	s, key, err := f.loadOwn(t)
	wantNoSession(t, s, key, err)
}

func TestLoadPassesOnAStoreFailure(t *testing.T) {
	f := newLoadFixture(t)
	down := errors.New("store unavailable")
	f.store.loadErr = down

	_, _, err := f.loadOwn(t)

	if !errors.Is(err, down) {
		t.Fatalf("load() error = %v, want the store's", err)
	}
	if errors.Is(err, ErrNoSession) {
		t.Error("a store failure reads as no session, which would sign the user out")
	}
}

func TestLoadStillReturnsTheSessionWhenTheTouchFails(t *testing.T) {
	f := newLoadFixture(t)
	f.store.saveErr = errors.New("store unavailable")
	f.now = signedIn.Add(2 * time.Hour)

	s, _, err := f.loadOwn(t)

	if err != nil {
		t.Fatalf("load() error = %v, want the session despite the failed touch", err)
	}
	if s.Subject != "user-1" {
		t.Errorf("session = %+v, want the stored one", s)
	}
}
