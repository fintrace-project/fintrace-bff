package session

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// An ML-DSA key: a kty jwkset does not support, which it must skip rather than fail the set on.
const unsupportedJWK = `{"kty":"AKP","kid":"pq-key","alg":"ML-DSA-44","pub":"AAAA"}`

type fakeJWKS struct {
	srv     *httptest.Server
	fetches atomic.Int32

	mu      sync.Mutex
	keys    []jose.JSONWebKey
	body    string
	status  int
	hold    chan struct{}
	arrived chan struct{}
}

func newFakeJWKS(t *testing.T, keys ...jose.JSONWebKey) *fakeJWKS {
	t.Helper()
	f := startFakeJWKS(keys...)
	t.Cleanup(f.srv.Close)
	return f
}

func startFakeJWKS(keys ...jose.JSONWebKey) *fakeJWKS {
	f := &fakeJWKS{keys: keys}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.fetches.Add(1)
		f.mu.Lock()
		keys, body, status, hold, arrived := f.keys, f.body, f.status, f.hold, f.arrived
		f.mu.Unlock()
		if arrived != nil {
			arrived <- struct{}{}
		}
		if hold != nil {
			<-hold
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: keys})
	}))
	return f
}

func (f *fakeJWKS) url() string { return f.srv.URL + "/certs" }

func (f *fakeJWKS) set(change func(f *fakeJWKS)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func publicJWK(key *rsa.PrivateKey, kid string) jose.JSONWebKey {
	return jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
}

func newTestKeySet(t *testing.T, f *fakeJWKS, refetchEvery, refreshEvery time.Duration) *keySet {
	t.Helper()
	ks, err := newKeySet(t.Context(), http.DefaultClient, f.url(), []jose.SignatureAlgorithm{jose.RS256},
		refetchEvery, refreshEvery)
	if err != nil {
		t.Fatalf("newKeySet() error = %v", err)
	}
	return ks
}

func keyToken(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	return signTokenWithKeyID(t, jose.RS256, key, kid, map[string]any{"sub": "user-1"})
}

func TestKeySetFetchesOnceAtConstructionAndVerifiesWithoutFetching(t *testing.T) {
	f := newFakeJWKS(t, publicJWK(issuerKey(), testKeyID))
	ks := newTestKeySet(t, f, time.Minute, time.Hour)
	if got := f.fetches.Load(); got != 1 {
		t.Fatalf("fetches after construction = %d, want 1", got)
	}

	payload, err := ks.VerifySignature(t.Context(), keyToken(t, issuerKey(), testKeyID))

	if err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}
	if !strings.Contains(string(payload), `"sub":"user-1"`) {
		t.Errorf("payload = %s, want the token's claims", payload)
	}
	if got := f.fetches.Load(); got != 1 {
		t.Errorf("fetches = %d, want still 1", got)
	}
}

func TestNewKeySetRefusesAnUnusableJWKS(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "the realm answering an error", status: http.StatusServiceUnavailable},
		{name: "a body that is not JSON", body: "<html>unavailable</html>"},
		{name: "an empty set", body: `{"keys":[]}`},
		{name: "only keys it cannot use", body: `{"keys":[` + unsupportedJWK + `]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeJWKS(t)
			f.set(func(f *fakeJWKS) { f.status, f.body = tt.status, tt.body })

			ks, err := newKeySet(t.Context(), http.DefaultClient, f.url(), []jose.SignatureAlgorithm{jose.RS256},
				time.Minute, time.Hour)

			if err == nil {
				t.Fatalf("newKeySet() = %+v, want an error", ks)
			}
			if !strings.Contains(err.Error(), "oidc keys at") {
				t.Errorf("error = %q, want it to name the key set", err)
			}
		})
	}
}

func TestKeySetSkipsAKeyItCannotParse(t *testing.T) {
	signing, err := json.Marshal(publicJWK(issuerKey(), testKeyID))
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeJWKS(t)
	f.set(func(f *fakeJWKS) { f.body = `{"keys":[` + unsupportedJWK + `,` + string(signing) + `]}` })
	ks := newTestKeySet(t, f, time.Minute, time.Hour)

	if _, err := ks.VerifySignature(t.Context(), keyToken(t, issuerKey(), testKeyID)); err != nil {
		t.Errorf("VerifySignature() error = %v, want the signing key beside the unsupported one to verify", err)
	}
}

func TestKeySetDoesNotFetchForAKnownKeyWithABadSignature(t *testing.T) {
	f := newFakeJWKS(t, publicJWK(issuerKey(), testKeyID))
	ks := newTestKeySet(t, f, time.Minute, time.Hour)
	forged := keyToken(t, newRSAKey(), testKeyID)

	for range 10 {
		if _, err := ks.VerifySignature(t.Context(), forged); err == nil {
			t.Fatal("VerifySignature() accepted a token signed by another key")
		}
	}

	if got := f.fetches.Load(); got != 1 {
		t.Errorf("fetches = %d, want 1 (construction only)", got)
	}
}

// The regression 5.3e exists for: junk tokens must not each become a call to the realm.
func TestKeySetFetchesOnceForABurstOfUnknownKeys(t *testing.T) {
	f := newFakeJWKS(t, publicJWK(issuerKey(), testKeyID))
	ks := newTestKeySet(t, f, time.Minute, time.Hour)
	other := newRSAKey()

	done := make(chan error, 1)
	go func() {
		for i := range 10 {
			if _, err := ks.VerifySignature(t.Context(), keyToken(t, other, fmt.Sprintf("unknown-%d", i))); err == nil {
				done <- fmt.Errorf("token %d with an unknown kid was accepted", i)
				return
			}
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("refusals waited on the rate limiter instead of failing at once")
	}
	if got := f.fetches.Load(); got != 2 {
		t.Errorf("fetches = %d, want 2 (construction and one refetch)", got)
	}
}

func TestKeySetFetchesOnceForConcurrentUnknownKeys(t *testing.T) {
	f := newFakeJWKS(t, publicJWK(issuerKey(), testKeyID))
	ks := newTestKeySet(t, f, time.Minute, time.Hour)
	other := newRSAKey()
	tokens := make([]string, 10)
	for i := range tokens {
		tokens[i] = keyToken(t, other, fmt.Sprintf("unknown-%d", i))
	}

	var wg sync.WaitGroup
	for _, token := range tokens {
		wg.Go(func() { _, _ = ks.VerifySignature(t.Context(), token) })
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refusals waited on the rate limiter instead of failing at once")
	}

	if got := f.fetches.Load(); got != 2 {
		t.Errorf("fetches = %d, want 2 (construction and one refetch)", got)
	}
}

func TestKeySetFetchesAgainOnceTheIntervalHasPassed(t *testing.T) {
	const interval = 100 * time.Millisecond
	f := newFakeJWKS(t, publicJWK(issuerKey(), testKeyID))
	ks := newTestKeySet(t, f, interval, time.Hour)
	unknown := keyToken(t, newRSAKey(), "unknown")

	_, _ = ks.VerifySignature(t.Context(), unknown)
	time.Sleep(interval + 50*time.Millisecond)
	_, _ = ks.VerifySignature(t.Context(), unknown)

	if got := f.fetches.Load(); got != 3 {
		t.Errorf("fetches = %d, want 3 (construction and one refetch per interval)", got)
	}
}

func TestKeySetPicksUpARotatedKey(t *testing.T) {
	f := newFakeJWKS(t, publicJWK(issuerKey(), testKeyID))
	ks := newTestKeySet(t, f, time.Minute, time.Hour)
	rotated := newRSAKey()
	f.set(func(f *fakeJWKS) { f.keys = append(f.keys, publicJWK(rotated, "key-2")) })

	if _, err := ks.VerifySignature(t.Context(), keyToken(t, rotated, "key-2")); err != nil {
		t.Fatalf("VerifySignature() error = %v, want the rotated key fetched and accepted", err)
	}
	if got := f.fetches.Load(); got != 2 {
		t.Errorf("fetches = %d, want 2", got)
	}
}

func TestKeySetKeepsItsKeysWhenTheRealmIsDown(t *testing.T) {
	f := newFakeJWKS(t, publicJWK(issuerKey(), testKeyID))
	ks := newTestKeySet(t, f, time.Minute, time.Hour)
	f.set(func(f *fakeJWKS) { f.status = http.StatusServiceUnavailable })

	if _, err := ks.VerifySignature(t.Context(), keyToken(t, newRSAKey(), "unknown")); err == nil {
		t.Fatal("VerifySignature() accepted an unknown kid while the realm was down")
	}
	if got := f.fetches.Load(); got != 2 {
		t.Fatalf("fetches = %d, want 2 (the refetch attempted)", got)
	}

	if _, err := ks.VerifySignature(t.Context(), keyToken(t, issuerKey(), testKeyID)); err != nil {
		t.Errorf("VerifySignature() error = %v, want the old key kept after a failed refetch", err)
	}
}

func TestKeySetFinishesARefetchItsCallerAbandoned(t *testing.T) {
	f := newFakeJWKS(t, publicJWK(issuerKey(), testKeyID))
	ks := newTestKeySet(t, f, time.Minute, time.Hour)
	rotated := newRSAKey()
	hold, arrived := make(chan struct{}), make(chan struct{}, 1)
	f.set(func(f *fakeJWKS) {
		f.keys = append(f.keys, publicJWK(rotated, "key-2"))
		f.hold, f.arrived = hold, arrived
	})
	token := keyToken(t, rotated, "key-2")

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := ks.VerifySignature(ctx, token)
		result <- err
	}()
	<-arrived
	cancel()
	close(hold)

	if err := <-result; err != nil {
		t.Errorf("abandoned VerifySignature() error = %v, want the refetch to finish regardless", err)
	}
	if _, err := ks.VerifySignature(t.Context(), token); err != nil {
		t.Errorf("VerifySignature() error = %v, want the key the abandoned refetch fetched", err)
	}
	if got := f.fetches.Load(); got != 2 {
		t.Errorf("fetches = %d, want 2", got)
	}
}

func TestKeySetDropsAWithdrawnKeyOnTheBackgroundRefresh(t *testing.T) {
	const refresh = 100 * time.Millisecond
	// Not closed: the refresh goroutine runs on a context that is never cancelled, and would log
	// a failed refresh every interval for the rest of the run against a closed server.
	f := startFakeJWKS(publicJWK(issuerKey(), testKeyID))
	replacement := newRSAKey()
	ks := newTestKeySet(t, f, time.Minute, refresh)
	var withdrawnAt int32
	f.set(func(f *fakeJWKS) {
		f.keys = []jose.JSONWebKey{publicJWK(replacement, "key-2")}
		withdrawnAt = f.fetches.Load()
	})

	// The counter moves when a request arrives, before jwkset swaps the keys in: the second arrival
	// after the withdrawal means the first has completed.
	deadline := time.Now().Add(2 * time.Second)
	for f.fetches.Load() < withdrawnAt+2 {
		if time.Now().After(deadline) {
			t.Fatal("no background refresh within 2 s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, err := ks.VerifySignature(t.Context(), keyToken(t, issuerKey(), testKeyID)); err == nil {
		t.Error("VerifySignature() accepted a key the realm has withdrawn")
	}
}
