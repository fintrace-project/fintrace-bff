package session

import (
	"context"
	"time"
)

type Session struct {
	UserID        string
	Subject       string
	AccessToken   string
	RefreshToken  string
	AccessExpiry  time.Time
	RefreshExpiry time.Time
	IDToken       string
	CreatedAt     time.Time
	LastSeen      time.Time
}

type UserIDResolver interface {
	UserID(ctx context.Context, accessToken string) (string, error)
}

func deadline(s Session, idle, max time.Duration) time.Time {
	tmin := s.LastSeen.Add(idle)
	if t2 := s.CreatedAt.Add(max); t2.Before(tmin) {
		tmin = t2
	}
	if t3 := s.RefreshExpiry; !t3.IsZero() && t3.Before(tmin) {
		tmin = t3
	}
	return tmin
}
