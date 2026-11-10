package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace/noop"

	"github.com/fintrace-project/fintrace-bff/internal/config"
	"github.com/fintrace-project/fintrace-bff/internal/csp"
	"github.com/fintrace-project/fintrace-bff/internal/server/proxy"
)

var styleNonce = regexp.MustCompile(`style-src 'self' 'nonce-([^']+)'`)

func nonceIn(t *testing.T, policy string) string {
	t.Helper()
	m := styleNonce.FindStringSubmatch(policy)
	if m == nil {
		t.Fatalf("policy %q carries no nonce in style-src", policy)
	}
	return m[1]
}

// serveSecured passes one request through the middleware alone and returns what the handler behind it got.
func serveSecured(t *testing.T, cfg config.Config) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	var seen *http.Request
	h := withSecurityHeaders(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = r }), cfg)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec, seen
}

func TestDefaultPolicyCarriesAFreshNonceForEachResponse(t *testing.T) {
	cfg := testConfig()

	first, seen := serveSecured(t, cfg)
	policy := first.Header().Get(cspHeader)
	nonce := nonceIn(t, policy)
	if want := csp.Policy(cfg.IssuerURI, nonce); policy != want {
		t.Errorf("policy = %q, want %q", policy, want)
	}
	if got, ok := csp.NonceFrom(seen.Context()); !ok || got != nonce {
		t.Errorf("the handler got nonce %q (%v), want the header's %q, or the page names another", got, ok, nonce)
	}

	second, _ := serveSecured(t, cfg)
	if again := nonceIn(t, second.Header().Get(cspHeader)); again == nonce {
		t.Errorf("two responses share nonce %q, want a fresh one each", nonce)
	}
}

func TestPolicyFromTheEnvironmentReplacesTheDefaultWhole(t *testing.T) {
	cfg := testConfig()
	cfg.ContentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline'"

	rec, seen := serveSecured(t, cfg)

	if got := rec.Header().Values(cspHeader); len(got) != 1 || got[0] != cfg.ContentSecurityPolicy {
		t.Errorf("policy = %q, want the variable's %q unchanged", got, cfg.ContentSecurityPolicy)
	}
	// A nonce would make browsers ignore the 'unsafe-inline' the dev policy relies on
	if got, ok := csp.NonceFrom(seen.Context()); ok {
		t.Errorf("the handler got nonce %q, want none beside a configured policy", got)
	}
}

func TestHSTSOnlyForAnHTTPSOrigin(t *testing.T) {
	cfg := testConfig()
	if got := securityHeaders(cfg).Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("HSTS = %q on an https origin, want max-age=31536000", got)
	}

	cfg.PublicOrigin = &url.URL{Scheme: "http", Host: "localhost:8100"}
	if got := securityHeaders(cfg).Values("Strict-Transport-Security"); len(got) != 0 {
		t.Errorf("HSTS = %q on an http origin, want none", got)
	}
}

// The proxy drops exactly the names the middleware sets: a name added to one side only would go unnoticed.
func TestSecurityHeadersAreTheNamesTheProxyDrops(t *testing.T) {
	rec, _ := serveSecured(t, testConfig())
	var set []string
	for name := range rec.Header() {
		set = append(set, name)
	}
	dropped := slices.Clone(proxy.SecurityHeaders)
	slices.Sort(set)
	slices.Sort(dropped)

	if !slices.Equal(set, dropped) {
		t.Errorf("the middleware sets %v, the proxy drops %v; want the same names", set, dropped)
	}
}

func TestEveryAnswerCarriesEachSecurityHeaderOnce(t *testing.T) {
	// An upstream sending its own: Spring's nosniff, and anything a web server might add.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src *")
		w.Header().Set("Referrer-Policy", "unsafe-url")
		w.Header().Set("Strict-Transport-Security", "max-age=1")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	tp := noop.NewTracerProvider()
	cfg := testConfig()
	upstreams := proxy.UpstreamProxies{
		Core:        proxy.NewProxy(target, proxy.NewTransport(tp, time.Second, slog.LevelInfo), cfg),
		MOKImporter: http.NotFoundHandler(),
		Web:         proxy.WithCSP(proxy.NewProxy(target, proxy.NewTransport(tp, time.Second, slog.LevelDebug), cfg)),
	}
	h, err := RoutesHandler(tp, &stubAuth{}, cfg, upstreams)
	if err != nil {
		t.Fatal(err)
	}
	fixed := securityHeaders(cfg)

	tests := []struct {
		name   string
		method string
		path   string
		origin string
		status int
	}{
		{name: "the web UI's answer", method: http.MethodGet, path: "/workspaces", status: http.StatusOK},
		{name: "Core's answer", method: http.MethodGet, path: "/api/v1/workspaces", status: http.StatusOK},
		{name: "the BFF's own 404", method: http.MethodGet, path: "/api/v1/unknown", status: http.StatusNotFound},
		{name: "the CSRF refusal", method: http.MethodPost, path: "/api/v1/workspaces",
			origin: "https://evil.example", status: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			for _, name := range proxy.SecurityHeaders {
				got := rec.Header().Values(name)
				if len(got) != 1 {
					t.Errorf("%s = %q, want exactly one, the BFF's", name, got)
					continue
				}
				want := fixed.Get(name)
				if name == cspHeader {
					want = csp.Policy(cfg.IssuerURI, nonceIn(t, got[0]))
				}
				if got[0] != want {
					t.Errorf("%s = %q, want the BFF's %q", name, got[0], want)
				}
			}
		})
	}
}
