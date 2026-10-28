package session

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/time/rate"
)

const (
	keyRefetchInterval = time.Minute
	keyRefreshInterval = time.Hour
	keyFetchTimeout    = 10 * time.Second
)

type keySet struct {
	storage jwkset.Storage
	algs    []jose.SignatureAlgorithm
}

var _ oidc.KeySet = (*keySet)(nil)

// VerifySignature implements [oidc.KeySet].
func (k *keySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt, k.algs)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %w", err)
	}

	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("token must have exactly 1 signature (it has %d)", len(jws.Signatures))
	}

	kid := jws.Signatures[0].Header.KeyID
	jwk, err := k.storage.KeyRead(context.WithoutCancel(ctx), kid)
	if err != nil {
		return nil, fmt.Errorf("key %q: %w", kid, err)
	}
	ks := oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{jwk.Key()}}
	return ks.VerifySignature(ctx, jwt)
}

func newKeySet(
	ctx context.Context,
	client *http.Client,
	jwksURL string,
	algs []jose.SignatureAlgorithm,
	refetchEvery,
	refreshEvery time.Duration,
) (*keySet, error) {
	storage, err := jwkset.NewStorageFromHTTP(jwksURL, jwkset.HTTPClientStorageOptions{
		Ctx:             ctx,
		Client:          client,
		HTTPTimeout:     keyFetchTimeout,
		RefreshInterval: refreshEvery,
		RefreshErrorHandler: func(ctx context.Context, err error) {
			slog.WarnContext(ctx, "OIDC keys not refreshed", "url", jwksURL, "error", err)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("oidc keys at %s: %w", jwksURL, err)
	}

	keys, err := jwkset.NewHTTPClient(jwkset.HTTPClientOptions{
		HTTPURLs:          map[string]jwkset.Storage{jwksURL: storage},
		RefreshUnknownKID: rate.NewLimiter(rate.Every(refetchEvery), 1),
		// Shorter than refetchEvery, so a refused caller fails at once instead of waiting for the next slot.
		RateLimitWaitMax: keyFetchTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("oidc keys at %s: %w", jwksURL, err)
	}

	all, err := keys.KeyReadAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("oidc keys at %s: %w", jwksURL, err)
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("oidc keys at %s: no usable key", jwksURL)
	}

	return &keySet{storage: keys, algs: algs}, nil
}
