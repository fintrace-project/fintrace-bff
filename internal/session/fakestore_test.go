package session

import (
	"context"
	"sync"
	"time"
)

type fakeEntry struct {
	session   Session
	expiresAt time.Time
}

// A Store for this package's tests, which cannot import memstore: memstore imports session.
// It keeps deadlines like a real store and fails on demand; tests read entries directly.
type fakeStore struct {
	now func() time.Time

	mu        sync.Mutex
	entries   map[StoreKey]fakeEntry
	saveErr   error
	loadErr   error
	deleteErr error
}

var _ Store = (*fakeStore)(nil)

func newFakeStore(now func() time.Time) *fakeStore {
	return &fakeStore{now: now, entries: make(map[StoreKey]fakeEntry)}
}

func (f *fakeStore) Save(_ context.Context, key StoreKey, s Session, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveErr != nil {
		return f.saveErr
	}
	f.entries[key] = fakeEntry{session: s, expiresAt: expiresAt}
	return nil
}

func (f *fakeStore) Load(_ context.Context, key StoreKey) (Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loadErr != nil {
		return Session{}, f.loadErr
	}
	e, ok := f.entries[key]
	if !ok || !f.now().Before(e.expiresAt) {
		return Session{}, ErrNoSession
	}
	return e.session, nil
}

func (f *fakeStore) Delete(_ context.Context, key StoreKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.entries, key)
	return nil
}
