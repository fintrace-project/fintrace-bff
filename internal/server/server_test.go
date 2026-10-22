package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/trace/noop"
)

func TestHealthz(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		path        string
		wantStatus  int
		wantBody    string
		wantType    string
		wantAllowed string
	}{
		{name: "GET answers UP", method: http.MethodGet, path: "/healthz",
			wantStatus: http.StatusOK, wantBody: `{"status":"UP"}`, wantType: "application/json"},
		{name: "HEAD answers without a body", method: http.MethodHead, path: "/healthz",
			wantStatus: http.StatusOK, wantType: "application/json"},
		{name: "POST is not allowed", method: http.MethodPost, path: "/healthz",
			wantStatus: http.StatusMethodNotAllowed, wantAllowed: "GET, HEAD"},
		{name: "a trailing slash is another path", method: http.MethodGet, path: "/healthz/",
			wantStatus: http.StatusNotFound},
		{name: "an unknown path is not found", method: http.MethodGet, path: "/nope",
			wantStatus: http.StatusNotFound},
	}
	// A real server rather than a recorder: only a server drops the body of a HEAD response.
	srv := httptest.NewServer(RoutesHandler(noop.NewTracerProvider()))
	t.Cleanup(srv.Close)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), tt.method, srv.URL+tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if tt.wantType != "" {
				if got := resp.Header.Get("Content-Type"); got != tt.wantType {
					t.Errorf("Content-Type = %q, want %q", got, tt.wantType)
				}
			}
			if tt.wantStatus == http.StatusOK && string(body) != tt.wantBody {
				t.Errorf("body = %q, want %q", body, tt.wantBody)
			}
			if tt.wantAllowed != "" {
				if got := resp.Header.Get("Allow"); got != tt.wantAllowed {
					t.Errorf("Allow = %q, want %q", got, tt.wantAllowed)
				}
			}
		})
	}
}
