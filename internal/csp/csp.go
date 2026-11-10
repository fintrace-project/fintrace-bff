package csp

import (
	"context"
)

const Placeholder = "__CSP_NONCE__"

type nonceKey struct{}

func WithNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, nonceKey{}, nonce)
}

func NonceFrom(ctx context.Context) (string, bool) {
	nonce, ok := ctx.Value(nonceKey{}).(string)
	return nonce, ok && nonce != ""
}
