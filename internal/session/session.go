package session

import "time"

type Session struct {
	Subject       string
	AccessToken   string
	RefreshToken  string
	AccessExpiry  time.Time
	RefreshExpiry time.Time
	IDToken       string
	CreatedAt     time.Time
	LastSeen      time.Time
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
