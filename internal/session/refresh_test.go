package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Answers the refresh grant the way Keycloak does: a refresh token is good for one use, and every
// answer rotates it, so a second refresh with the same token is refused with invalid_grant.
type refreshRealm struct {
	t           *testing.T
	delay       time.Duration
	failStatus  int
	subject     string
	signingKey  any
	omitIDToken bool

	mu      sync.Mutex
	calls   int
	current string
	form    url.Values
	user    string
}

func (rr *refreshRealm) serve(w http.ResponseWriter, r *http.Request, issuer string) {
	if err := r.ParseForm(); err != nil {
		rr.t.Errorf("token request form: %v", err)
	}
	time.Sleep(rr.delay)
	user, _, _ := r.BasicAuth()

	rr.mu.Lock()
	rr.calls++
	n := rr.calls
	rr.form, rr.user = r.PostForm, user
	valid := r.PostForm.Get("grant_type") == "refresh_token" && r.PostForm.Get("refresh_token") == rr.current
	if valid && rr.failStatus == 0 {
		rr.current = fmt.Sprintf("refresh-%d", n)
	}
	rr.mu.Unlock()

	if rr.failStatus != 0 {
		http.Error(w, "realm unavailable", rr.failStatus)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !valid {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"Token is not active"}`)
		return
	}

	body := map[string]any{
		"access_token":       fmt.Sprintf("access-%d", n),
		"refresh_token":      fmt.Sprintf("refresh-%d", n),
		"token_type":         "Bearer",
		"expires_in":         300,
		"refresh_expires_in": 1800,
	}
	if !rr.omitIDToken {
		claims := idTokenClaims(issuer)
		if rr.subject != "" {
			claims["sub"] = rr.subject
		}
		key := rr.signingKey
		if key == nil {
			key = issuerKey()
		}
		body["id_token"] = signToken(rr.t, jose.RS256, key, claims)
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (rr *refreshRealm) recorded() (calls int, form url.Values, user string) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return rr.calls, rr.form, rr.user
}

var accessExpiry = signedIn.Add(5 * time.Minute)

type refreshFixture struct {
	a     *Auth
	store *fakeStore
	realm *refreshRealm
	srv   *httptest.Server
	now   time.Time
}

// A stored session whose access token lapses at accessExpiry, against a realm that accepts its
// refresh token once; the store and Auth read the same clock, so moving f.now moves both.
func newRefreshFixture(t *testing.T, realm *refreshRealm) *refreshFixture {
	t.Helper()
	realm.t = t
	realm.current = "refresh-0"
	f := &refreshFixture{realm: realm, now: signedIn}
	f.srv = newFakeRealm(t, nil, realm.serve)
	clock := func() time.Time { return f.now }
	f.store = newFakeStore(clock)

	a, err := NewAuth(t.Context(), testConfig(t, f.srv.URL), http.DefaultClient, f.store)
	if err != nil {
		t.Fatalf("NewAuth() error = %v", err)
	}
	a.now = clock
	f.a = a

	s := Session{Subject: "user-1", AccessToken: "access-0", RefreshToken: "refresh-0", AccessExpiry: accessExpiry,
		IDToken: "id-token-0", CreatedAt: signedIn, LastSeen: signedIn}
	if err := f.store.Save(t.Context(), asStoreKey(loadTestID), s, deadline(s, testSessionIdle, testSessionMax)); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *refreshFixture) load(t *testing.T) (Session, error) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/anything", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: loadTestID})
	s, _, err := f.a.load(req)
	return s, err
}

func (f *refreshFixture) stored(t *testing.T) (fakeEntry, bool) {
	t.Helper()
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	e, ok := f.store.entries[asStoreKey(loadTestID)]
	return e, ok
}

func (f *refreshFixture) calls() int {
	calls, _, _ := f.realm.recorded()
	return calls
}

func TestLoadRefreshesWithinAMinuteOfExpiry(t *testing.T) {
	tests := []struct {
		name      string
		at        time.Time
		refreshed bool
	}{
		{name: "61 seconds before expiry", at: accessExpiry.Add(-61 * time.Second)},
		{name: "a minute before expiry", at: accessExpiry.Add(-time.Minute), refreshed: true},
		{name: "30 seconds before expiry", at: accessExpiry.Add(-30 * time.Second), refreshed: true},
		{name: "an hour after expiry, back from idle", at: accessExpiry.Add(time.Hour), refreshed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRefreshFixture(t, &refreshRealm{})
			f.now = tt.at

			s, err := f.load(t)
			if err != nil {
				t.Fatalf("load() error = %v", err)
			}

			want, wantCalls := "access-0", 0
			if tt.refreshed {
				want, wantCalls = "access-1", 1
			}
			if got := f.calls(); got != wantCalls {
				t.Errorf("%d token requests, want %d", got, wantCalls)
			}
			if s.AccessToken != want {
				t.Errorf("AccessToken = %q, want %q", s.AccessToken, want)
			}
		})
	}
}

func TestLoadStoresTheRefreshedSession(t *testing.T) {
	f := newRefreshFixture(t, &refreshRealm{})
	f.now = accessExpiry.Add(-30 * time.Second)

	before := time.Now()
	s, err := f.load(t)
	after := time.Now()
	if err != nil {
		t.Fatalf("load() error = %v", err)
	}

	_, form, user := f.realm.recorded()
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "refresh-0" {
		t.Errorf("token request = %v, want the refresh grant with the stored refresh token", form)
	}
	if user != "fintrace-bff" {
		t.Errorf("client authenticated as %q, want fintrace-bff", user)
	}

	e, ok := f.stored(t)
	if !ok {
		t.Fatal("the session is no longer stored")
	}
	if e.session != s {
		t.Errorf("stored %+v, but load returned %+v", e.session, s)
	}
	if s.AccessToken != "access-1" || s.RefreshToken != "refresh-1" {
		t.Errorf("tokens = %q, %q, want the realm's new ones", s.AccessToken, s.RefreshToken)
	}
	if s.IDToken == "" || s.IDToken == "id-token-0" {
		t.Error("the refreshed ID token was not kept, and sign-out sends it as the hint")
	}
	// oauth2 dates the access token's expiry by the real clock, not the injected one
	if s.AccessExpiry.Before(before.Add(300*time.Second)) || s.AccessExpiry.After(after.Add(300*time.Second)) {
		t.Errorf("AccessExpiry = %v, want about five minutes after the refresh", s.AccessExpiry)
	}
	if want := f.now.Add(30 * time.Minute); !s.RefreshExpiry.Equal(want) {
		t.Errorf("RefreshExpiry = %v, want %v from refresh_expires_in", s.RefreshExpiry, want)
	}
	if s.Subject != "user-1" || !s.CreatedAt.Equal(signedIn) || !s.LastSeen.Equal(f.now) {
		t.Errorf("Subject = %q, CreatedAt = %v, LastSeen = %v; want user-1, %v and %v",
			s.Subject, s.CreatedAt, s.LastSeen, signedIn, f.now)
	}
	// The new refresh token's half hour is now the earliest of the three limits
	if want := f.now.Add(30 * time.Minute); !e.expiresAt.Equal(want) {
		t.Errorf("stored until %v, want %v", e.expiresAt, want)
	}
}

func TestLoadRefreshesOnceForConcurrentRequests(t *testing.T) {
	// A slow realm, so requests without one flight per session would all send the same refresh token
	f := newRefreshFixture(t, &refreshRealm{delay: 100 * time.Millisecond})
	f.now = accessExpiry.Add(-30 * time.Second)

	const n = 10
	sessions := make([]Session, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { sessions[i], errs[i] = f.load(t) })
	}
	wg.Wait()

	if got := f.calls(); got != 1 {
		t.Errorf("%d token requests, want 1", got)
	}
	for i := range n {
		if errs[i] != nil {
			t.Errorf("request %d: load() error = %v", i, errs[i])
		} else if sessions[i].AccessToken != "access-1" {
			t.Errorf("request %d: AccessToken = %q, want access-1", i, sessions[i].AccessToken)
		}
	}
	if e, ok := f.stored(t); !ok || e.session.RefreshToken != "refresh-1" {
		t.Errorf("stored = %+v, want the session holding refresh-1", e.session)
	}
}

func TestLoadAfterARefreshUsesTheRefreshedSession(t *testing.T) {
	f := newRefreshFixture(t, &refreshRealm{})
	f.now = accessExpiry.Add(-30 * time.Second)
	if _, err := f.load(t); err != nil {
		t.Fatalf("first load() error = %v", err)
	}

	// Within the same second, and then once a touch is due: neither may refresh again or write back refresh-0
	for _, later := range []time.Duration{0, 2 * time.Minute} {
		f.now = accessExpiry.Add(-30 * time.Second).Add(later)
		s, err := f.load(t)
		if err != nil {
			t.Fatalf("load() %v later error = %v", later, err)
		}
		if s.AccessToken != "access-1" {
			t.Errorf("load() %v later: AccessToken = %q, want access-1", later, s.AccessToken)
		}
	}

	if got := f.calls(); got != 1 {
		t.Errorf("%d token requests, want 1", got)
	}
	e, ok := f.stored(t)
	if !ok {
		t.Fatal("the session is no longer stored")
	}
	if e.session.RefreshToken != "refresh-1" {
		t.Errorf("stored RefreshToken = %q, want refresh-1", e.session.RefreshToken)
	}
	if want := accessExpiry.Add(-30 * time.Second).Add(2 * time.Minute); !e.session.LastSeen.Equal(want) {
		t.Errorf("stored LastSeen = %v, want the touch at %v", e.session.LastSeen, want)
	}
}

func TestLoadEndsTheSessionWhenTheRealmRefusesTheRefreshToken(t *testing.T) {
	f := newRefreshFixture(t, &refreshRealm{})
	f.realm.current = "refresh-elsewhere"
	f.now = accessExpiry.Add(-30 * time.Second)

	_, err := f.load(t)

	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("load() error = %v, want ErrNoSession", err)
	}
	if _, ok := f.stored(t); ok {
		t.Error("the session is still stored")
	}
}

func TestLoadKeepsTheSessionWhenTheRealmIsUnavailable(t *testing.T) {
	failures := []struct {
		name  string
		setup func(f *refreshFixture)
	}{
		{name: "the realm answers 503", setup: func(f *refreshFixture) { f.realm.failStatus = http.StatusServiceUnavailable }},
		{name: "the realm is unreachable", setup: func(f *refreshFixture) { f.srv.Close() }},
		{name: "the refreshed ID token does not verify", setup: func(f *refreshFixture) { f.realm.signingKey = newRSAKey() }},
	}
	for _, failure := range failures {
		t.Run(failure.name+", before the access token lapses", func(t *testing.T) {
			f := newRefreshFixture(t, &refreshRealm{})
			failure.setup(f)
			f.now = accessExpiry.Add(-30 * time.Second)

			s, err := f.load(t)

			if err != nil {
				t.Fatalf("load() error = %v, want the stored session while its access token still works", err)
			}
			if s.AccessToken != "access-0" {
				t.Errorf("AccessToken = %q, want the stored access-0", s.AccessToken)
			}
			wantUnchanged(t, f)
		})
		t.Run(failure.name+", after the access token lapsed", func(t *testing.T) {
			f := newRefreshFixture(t, &refreshRealm{})
			failure.setup(f)
			f.now = accessExpiry.Add(time.Second)

			_, err := f.load(t)

			if err == nil || errors.Is(err, ErrNoSession) {
				t.Fatalf("load() error = %v, want an error other than ErrNoSession, so the caller answers 503", err)
			}
			wantUnchanged(t, f)
		})
	}
}

func wantUnchanged(t *testing.T, f *refreshFixture) {
	t.Helper()
	e, ok := f.stored(t)
	if !ok {
		t.Fatal("the session was dropped")
	}
	if e.session.RefreshToken != "refresh-0" || !e.session.LastSeen.Equal(signedIn) {
		t.Errorf("stored = %+v, want it unchanged", e.session)
	}
}

func TestLoadKeepsTheIDTokenWhenTheRefreshCarriesNone(t *testing.T) {
	f := newRefreshFixture(t, &refreshRealm{omitIDToken: true})
	f.now = accessExpiry.Add(-30 * time.Second)

	s, err := f.load(t)

	if err != nil {
		t.Fatalf("load() error = %v", err)
	}
	if s.AccessToken != "access-1" || s.IDToken != "id-token-0" {
		t.Errorf("AccessToken = %q, IDToken = %q; want access-1 and the earlier ID token", s.AccessToken, s.IDToken)
	}
}

func TestLoadEndsTheSessionWhenTheRefreshedIDTokenNamesAnotherSubject(t *testing.T) {
	f := newRefreshFixture(t, &refreshRealm{subject: "user-2"})
	f.now = accessExpiry.Add(-30 * time.Second)

	_, err := f.load(t)

	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("load() error = %v, want ErrNoSession", err)
	}
	if _, ok := f.stored(t); ok {
		t.Error("the session is still stored")
	}
}
