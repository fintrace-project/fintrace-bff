package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/fintrace-project/fintrace-bff/internal/config"
)

const testPublicOrigin = "https://fintrace.example"

func testConfig() config.Config {
	return config.Config{PublicOrigin: &url.URL{Scheme: "https", Host: "fintrace.example"}}
}

func TestCSRF(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		origin      string
		fetchSite   string
		wantReached bool
		why         string
	}{
		{name: "POST from the public origin passes", method: http.MethodPost, origin: testPublicOrigin,
			wantReached: true, why: "or the web UI could not sign out"},
		{name: "POST from a foreign origin is refused", method: http.MethodPost, origin: "https://evil.example",
			why: "or a cross-site form could act as the user"},
		{name: "POST without Origin is refused", method: http.MethodPost,
			why: "or a request stripped of its Origin is waved through"},
		{name: "POST from an opaque origin is refused", method: http.MethodPost, origin: "null",
			why: "or a sandboxed frame could act as the user"},
		{name: "cross-site POST is refused", method: http.MethodPost, origin: "https://evil.example", fetchSite: "cross-site",
			why: "or a cross-site form could act as the user"},
		{name: "GET without Origin passes", method: http.MethodGet,
			wantReached: true, why: "or a link or a reload would be refused"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})

			// The request's Host is example.com, so only the trusted origin can let the public origin through.
			req := httptest.NewRequestWithContext(t.Context(), tt.method, authSignOutPath, nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tt.fetchSite)
			}
			csrf, err := withCSRF(next, testConfig())
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			csrf.ServeHTTP(rec, req)

			if reached != tt.wantReached {
				t.Fatalf("handler reached = %t, want %t, %s", reached, tt.wantReached, tt.why)
			}
			if !tt.wantReached && rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
		})
	}
}

func TestCSRFExemptsOnlyABearerUnderAPI(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		authorization string
		origin        string
		wantReached   bool
		why           string
	}{
		{name: "Bearer under /api without Origin passes", path: "/api/v1/workspaces",
			authorization: "Bearer caller-token", wantReached: true, why: "or fintrace-smoke and the CLI could not write"},
		{name: "Bearer under /api from a foreign origin passes", path: "/api/v1/workspaces",
			authorization: "Bearer caller-token", origin: "https://evil.example", wantReached: true,
			why: "since a cross-site page cannot attach the header, and the token decides"},
		{name: "a lower-case scheme passes", path: "/api/v1/workspaces",
			authorization: "bearer caller-token", wantReached: true, why: "or the exemption and the routing disagree"},
		{name: "Bearer on sign-out from a foreign origin is refused", path: authSignOutPath,
			authorization: "Bearer caller-token", origin: "https://evil.example",
			why: "or a header would lift the check from a handler that reads the cookie"},
		{name: "Basic under /api without Origin is refused", path: "/api/v1/workspaces",
			authorization: "Basic dXNlcjpwYXNz", why: "or a browser's own Basic credentials would skip the check"},
		{name: "no Authorization under /api without Origin is refused", path: "/api/v1/workspaces",
			why: "or the session path would lose its check"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tt.path, nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			csrf, err := withCSRF(next, testConfig())
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			csrf.ServeHTTP(rec, req)

			if reached != tt.wantReached {
				t.Fatalf("handler reached = %t, want %t, %s", reached, tt.wantReached, tt.why)
			}
			if !tt.wantReached && rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
		})
	}
}
