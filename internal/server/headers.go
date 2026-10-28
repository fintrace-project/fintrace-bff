package server

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/fintrace-project/fintrace-bff/internal/config"
)

// securityHeaders sets every name in proxy.SecurityHeaders, which the proxy drops from upstream answers.
func securityHeaders(cfg config.Config) http.Header {
	h := http.Header{}
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	csp := cfg.ContentSecurityPolicy
	if csp == "" {
		csp = defaultContentSecurityPolicy(cfg.IssuerURI)
	}
	h.Set("Content-Security-Policy", csp)
	if cfg.PublicOrigin.Scheme == "https" {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	return h
}

// Logout is a form POST redirected to the realm, and Chromium applies form-action to that redirect. A source
// with a path matches that path only, so the realm is named by its origin.
func defaultContentSecurityPolicy(issuer *url.URL) string {
	realm := (&url.URL{Scheme: issuer.Scheme, Host: issuer.Host}).String()
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self' " + realm,
		"frame-ancestors 'none'",
	}, "; ")
}

func withSecurityHeaders(next http.Handler, headers http.Header) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, values := range headers {
			w.Header()[name] = slices.Clone(values)
		}
		next.ServeHTTP(w, r)
	})
}
