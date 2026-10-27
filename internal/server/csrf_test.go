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
