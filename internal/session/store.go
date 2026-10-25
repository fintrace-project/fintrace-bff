package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

type StoreKey string

func asStoreKey(id string) StoreKey {
	sum := sha256.Sum256([]byte(id))
	return StoreKey(hex.EncodeToString(sum[:]))
}

type Store interface {
	Save(ctx context.Context, key StoreKey, s Session, expiresAt time.Time) error
	Load(ctx context.Context, key StoreKey) (Session, error)
	Delete(ctx context.Context, key StoreKey) error
}

var ErrNoSession = errors.New("no session")

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
