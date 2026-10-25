package session

import (
	"crypto/rand"
	"regexp"
	"strings"
	"testing"
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
