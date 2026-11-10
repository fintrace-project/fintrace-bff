package server

import (
	"crypto/rand"
	"net/http"
	"slices"

	"github.com/fintrace-project/fintrace-bff/internal/config"
	"github.com/fintrace-project/fintrace-bff/internal/csp"
)

const cspHeader = "Content-Security-Policy"

// securityHeaders are the headers alike on every response; the policy is set per response.
func securityHeaders(cfg config.Config) http.Header {
	h := http.Header{}
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	if cfg.PublicOrigin.Scheme == "https" {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	return h
}

func withSecurityHeaders(next http.Handler, cfg config.Config) http.Handler {
	headers := securityHeaders(cfg)
	configured, issuer := cfg.ContentSecurityPolicy, cfg.IssuerURI
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, values := range headers {
			w.Header()[name] = slices.Clone(values)
		}
		// A nonce makes browsers ignore 'unsafe-inline', which the configured dev policy relies on
		if configured != "" {
			w.Header().Set(cspHeader, configured)
			next.ServeHTTP(w, r)
			return
		}

		nonce := rand.Text()
		w.Header().Set(cspHeader, csp.Policy(issuer, nonce))
		next.ServeHTTP(w, r.WithContext(csp.WithNonce(r.Context(), nonce)))
	})
}
