package csp

import (
	"net/url"
	"strings"
)

func Policy(issuer *url.URL, nonce string) string {
	realm := (&url.URL{Scheme: issuer.Scheme, Host: issuer.Host}).String()
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'nonce-" + nonce + "'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self' " + realm,
		"frame-ancestors 'none'",
	}, "; ")
}
