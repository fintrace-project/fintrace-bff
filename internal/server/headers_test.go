package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace/noop"

	"github.com/fintrace-project/fintrace-bff/internal/server/proxy"
)

func TestDefaultPolicyNamesTheRealmByItsOriginInFormAction(t *testing.T) {
	csp := securityHeaders(testConfig()).Get("Content-Security-Policy")

	if !strings.Contains(csp, "form-action 'self' https://realm.example;") {
		t.Errorf("policy %q, want form-action naming the realm's origin, or logout's redirect is blocked", csp)
	}
	if strings.Contains(csp, "/realms") {
		t.Errorf("policy %q names the issuer's path, which would match only that path", csp)
	}
	for _, directive := range []string{"script-src 'self';", "frame-ancestors 'none'", "object-src 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("policy %q lacks %q", csp, directive)
		}
	}
}

func TestPolicyFromTheEnvironmentReplacesTheDefaultWhole(t *testing.T) {
	cfg := testConfig()
	cfg.ContentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline'"

	if got := securityHeaders(cfg).Get("Content-Security-Policy"); got != cfg.ContentSecurityPolicy {
		t.Errorf("policy = %q, want the variable's %q unchanged", got, cfg.ContentSecurityPolicy)
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
	var set []string
	for name := range securityHeaders(testConfig()) {
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
	upstreams := proxy.ExtClients{
		Core:        proxy.NewProxy(target, proxy.NewTransport(tp, time.Second, slog.LevelInfo), cfg),
		MOKImporter: http.NotFoundHandler(),
		Web:         proxy.NewProxy(target, proxy.NewTransport(tp, time.Second, slog.LevelDebug), cfg),
	}
	h, err := RoutesHandler(tp, &stubAuth{}, cfg, upstreams)
	if err != nil {
		t.Fatal(err)
	}
	want := securityHeaders(cfg)

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
				if len(got) != 1 || got[0] != want.Get(name) {
					t.Errorf("%s = %q, want exactly the BFF's %q", name, got, want.Get(name))
				}
			}
		})
	}
}
