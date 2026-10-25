package session

import (
	"testing"
	"time"
)

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
