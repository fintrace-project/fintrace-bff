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
