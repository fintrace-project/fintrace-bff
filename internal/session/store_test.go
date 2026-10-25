package session

import (
	"crypto/rand"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestAsStoreKeyIsTheHexSHA256OfTheID(t *testing.T) {
	// The FIPS 180-2 test vector, so the hash and its encoding are pinned, not just "some digest"
	const want = StoreKey("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	if got := asStoreKey("abc"); got != want {
		t.Errorf("asStoreKey(%q) = %q, want %q", "abc", got, want)
	}
}

func TestAsStoreKeyNeverHoldsTheID(t *testing.T) {
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	id := rand.Text()

	key := asStoreKey(id)

	if !hex64.MatchString(string(key)) {
		t.Errorf("asStoreKey() = %q, want 64 lowercase hex characters", key)
	}
	if strings.Contains(string(key), id) {
		t.Errorf("asStoreKey() = %q holds the id %q", key, id)
	}
	if again := asStoreKey(id); again != key {
		t.Errorf("asStoreKey() of the same id = %q, then %q", key, again)
	}
	if other := asStoreKey(rand.Text()); other == key {
		t.Errorf("asStoreKey() of two ids are both %q", key)
	}
}

func TestDeadline(t *testing.T) {
	const (
		idle   = 7 * 24 * time.Hour
		maxAge = 30 * 24 * time.Hour
	)
	signedIn := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		s    Session
		want time.Time
	}{
		{
			name: "a fresh session ends when it goes idle",
			s:    Session{CreatedAt: signedIn, LastSeen: signedIn},
			want: signedIn.Add(idle),
		},
		{
			name: "a session in use ends at its maximum",
			s:    Session{CreatedAt: signedIn, LastSeen: signedIn.Add(29 * 24 * time.Hour)},
			want: signedIn.Add(maxAge),
		},
		{
			name: "an earlier refresh expiry ends it first",
			s: Session{CreatedAt: signedIn, LastSeen: signedIn,
				RefreshExpiry: signedIn.Add(time.Hour)},
			want: signedIn.Add(time.Hour),
		},
		{
			name: "a later refresh expiry does not extend it",
			s: Session{CreatedAt: signedIn, LastSeen: signedIn,
				RefreshExpiry: signedIn.Add(365 * 24 * time.Hour)},
			want: signedIn.Add(idle),
		},
		{
			name: "a later refresh expiry does not extend it past its maximum",
			s: Session{CreatedAt: signedIn, LastSeen: signedIn.Add(29 * 24 * time.Hour),
				RefreshExpiry: signedIn.Add(365 * 24 * time.Hour)},
			want: signedIn.Add(maxAge),
		},
		{
			name: "no refresh expiry is no limit, not one already passed",
			s:    Session{CreatedAt: signedIn, LastSeen: signedIn, RefreshExpiry: time.Time{}},
			want: signedIn.Add(idle),
		},
		{
			name: "limits falling on the same instant",
			s: Session{CreatedAt: signedIn, LastSeen: signedIn.Add(maxAge - idle),
				RefreshExpiry: signedIn.Add(maxAge)},
			want: signedIn.Add(maxAge),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deadline(tt.s, idle, maxAge); !got.Equal(tt.want) {
				t.Errorf("deadline() = %v, want %v", got, tt.want)
			}
		})
	}
}
