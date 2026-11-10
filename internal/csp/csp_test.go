package csp

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

var issuer = &url.URL{Scheme: "https", Host: "realm.example", Path: "/realms/fintrace"}

func TestPolicyNamesTheRealmByItsOriginInFormAction(t *testing.T) {
	policy := Policy(issuer, "n0nce")

	if !strings.Contains(policy, "form-action 'self' https://realm.example;") {
		t.Errorf("policy %q, want form-action naming the realm's origin, or logout's redirect is blocked", policy)
	}
	if strings.Contains(policy, "/realms") {
		t.Errorf("policy %q names the issuer's path, which would match only that path", policy)
	}
	for _, directive := range []string{"script-src 'self';", "frame-ancestors 'none'", "object-src 'none'"} {
		if !strings.Contains(policy, directive) {
			t.Errorf("policy %q lacks %q", policy, directive)
		}
	}
}

// Scripts are all files, so the nonce belongs to style-src alone: Radix's scroll lock adds a <style>.
func TestPolicyCarriesTheNonceInStyleSrcOnly(t *testing.T) {
	policy := Policy(issuer, "n0nce")

	if !strings.Contains(policy, "style-src 'self' 'nonce-n0nce';") {
		t.Errorf("policy %q, want style-src allowing the nonce", policy)
	}
	if n := strings.Count(policy, "nonce-"); n != 1 {
		t.Errorf("policy %q names a nonce %d times, want once", policy, n)
	}
}

func TestNonceFrom(t *testing.T) {
	tests := []struct {
		name   string
		ctx    context.Context
		want   string
		wantOK bool
	}{
		{name: "a nonce stored", ctx: WithNonce(context.Background(), "n0nce"), want: "n0nce", wantOK: true},
		{name: "none stored", ctx: context.Background()},
		{name: "an empty one stored", ctx: WithNonce(context.Background(), "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NonceFrom(tt.ctx)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("NonceFrom = %q, %v; want %q, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
