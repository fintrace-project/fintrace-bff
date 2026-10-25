package storetest

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/session"
)

var signedIn = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

type clock struct {
	now time.Time
}

func (c *clock) Now() time.Time { return c.now }

func (c *clock) set(t time.Time) { c.now = t }

// Run checks that a Store keeps the contract the session package relies on, whatever holds the data.
func Run(t *testing.T, newStore func(now func() time.Time) session.Store) {
	tests := []struct {
		name string
		test func(t *testing.T, s session.Store, c *clock)
	}{
		{"save then load", testSaveThenLoad},
		{"an unknown key is no session", testUnknownKey},
		{"found until its deadline", testFoundBeforeDeadline},
		{"gone at its deadline", testGoneAtDeadline},
		{"gone after its deadline", testGoneAfterDeadline},
		{"saving again replaces the session and a later deadline", testSaveReplacesLater},
		{"saving again replaces an earlier deadline", testSaveReplacesEarlier},
		{"delete", testDelete},
		{"deleting an unknown key twice", testDeleteUnknown},
		{"keys are separate", testKeysAreSeparate},
		{"concurrent use", testConcurrentUse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &clock{now: signedIn}
			tt.test(t, newStore(c.Now), c)
		})
	}
}

func sample(subject string) session.Session {
	return session.Session{
		Subject:       subject,
		AccessToken:   "access-" + subject,
		RefreshToken:  "refresh-" + subject,
		AccessExpiry:  signedIn.Add(5 * time.Minute),
		RefreshExpiry: signedIn.Add(time.Hour),
		IDToken:       "id-" + subject,
		CreatedAt:     signedIn,
		LastSeen:      signedIn,
	}
}

func save(t *testing.T, s session.Store, key session.StoreKey, sess session.Session, expiresAt time.Time) {
	t.Helper()
	if err := s.Save(t.Context(), key, sess, expiresAt); err != nil {
		t.Fatalf("Save(%q) error = %v", key, err)
	}
}

func wantSession(t *testing.T, s session.Store, key session.StoreKey, want session.Session) {
	t.Helper()
	got, err := s.Load(t.Context(), key)
	if err != nil {
		t.Fatalf("Load(%q) error = %v, want the session", key, err)
	}
	if got != want {
		t.Errorf("Load(%q) = %+v, want %+v", key, got, want)
	}
}

func wantNoSession(t *testing.T, s session.Store, key session.StoreKey) {
	t.Helper()
	got, err := s.Load(t.Context(), key)
	if !errors.Is(err, session.ErrNoSession) {
		t.Fatalf("Load(%q) = %+v, %v; want ErrNoSession", key, got, err)
	}
	if got != (session.Session{}) {
		t.Errorf("Load(%q) = %+v alongside ErrNoSession, want the zero Session", key, got)
	}
}

func testSaveThenLoad(t *testing.T, s session.Store, _ *clock) {
	save(t, s, "k", sample("alice"), signedIn.Add(time.Hour))
	wantSession(t, s, "k", sample("alice"))
}

func testUnknownKey(t *testing.T, s session.Store, _ *clock) {
	wantNoSession(t, s, "missing")
}

func testFoundBeforeDeadline(t *testing.T, s session.Store, c *clock) {
	deadline := signedIn.Add(time.Hour)
	save(t, s, "k", sample("alice"), deadline)
	c.set(deadline.Add(-time.Nanosecond))
	wantSession(t, s, "k", sample("alice"))
}

func testGoneAtDeadline(t *testing.T, s session.Store, c *clock) {
	deadline := signedIn.Add(time.Hour)
	save(t, s, "k", sample("alice"), deadline)
	c.set(deadline)
	wantNoSession(t, s, "k")
}

func testGoneAfterDeadline(t *testing.T, s session.Store, c *clock) {
	deadline := signedIn.Add(time.Hour)
	save(t, s, "k", sample("alice"), deadline)
	c.set(deadline.Add(24 * time.Hour))
	wantNoSession(t, s, "k")
}

func testSaveReplacesLater(t *testing.T, s session.Store, c *clock) {
	save(t, s, "k", sample("alice"), signedIn.Add(time.Hour))
	save(t, s, "k", sample("bob"), signedIn.Add(2*time.Hour))
	c.set(signedIn.Add(90 * time.Minute))
	wantSession(t, s, "k", sample("bob"))
}

func testSaveReplacesEarlier(t *testing.T, s session.Store, c *clock) {
	save(t, s, "k", sample("alice"), signedIn.Add(2*time.Hour))
	save(t, s, "k", sample("alice"), signedIn.Add(time.Hour))
	c.set(signedIn.Add(90 * time.Minute))
	wantNoSession(t, s, "k")
}

func testDelete(t *testing.T, s session.Store, _ *clock) {
	save(t, s, "k", sample("alice"), signedIn.Add(time.Hour))
	if err := s.Delete(t.Context(), "k"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	wantNoSession(t, s, "k")
}

func testDeleteUnknown(t *testing.T, s session.Store, _ *clock) {
	for range 2 {
		if err := s.Delete(t.Context(), "missing"); err != nil {
			t.Fatalf("Delete() of an unknown key error = %v, want none", err)
		}
	}
}

func testKeysAreSeparate(t *testing.T, s session.Store, _ *clock) {
	save(t, s, "k1", sample("alice"), signedIn.Add(time.Hour))
	save(t, s, "k2", sample("bob"), signedIn.Add(time.Hour))
	if err := s.Delete(t.Context(), "k1"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	wantNoSession(t, s, "k1")
	wantSession(t, s, "k2", sample("bob"))
}

// Only means something under -race: a store missing a lock passes it without the detector.
func testConcurrentUse(t *testing.T, s session.Store, _ *clock) {
	const (
		goroutines = 8
		rounds     = 100
	)
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Go(func() {
			own := session.StoreKey(fmt.Sprintf("own-%d", g))
			for range rounds {
				for _, key := range []session.StoreKey{"shared", own} {
					if err := s.Save(t.Context(), key, sample("alice"), signedIn.Add(time.Hour)); err != nil {
						t.Errorf("Save(%q) error = %v", key, err)
					}
					if _, err := s.Load(t.Context(), key); err != nil && !errors.Is(err, session.ErrNoSession) {
						t.Errorf("Load(%q) error = %v", key, err)
					}
					if err := s.Delete(t.Context(), key); err != nil {
						t.Errorf("Delete(%q) error = %v", key, err)
					}
				}
			}
		})
	}
	wg.Wait()
}
