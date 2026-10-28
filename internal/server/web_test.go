package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace/noop"

	"github.com/fintrace-project/fintrace-bff/internal/server/proxy"
)

type webCall struct {
	method  string
	path    string
	cookie  string
	auth    string
	upgrade string
}

type fakeWeb struct {
	url   *url.URL
	mu    sync.Mutex
	calls []webCall
}

func newFakeWeb(t *testing.T) *fakeWeb {
	t.Helper()
	web := &fakeWeb{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		web.mu.Lock()
		web.calls = append(web.calls, webCall{method: r.Method, path: r.URL.Path, cookie: r.Header.Get("Cookie"),
			auth: r.Header.Get("Authorization"), upgrade: r.Header.Get("Upgrade")})
		web.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html>"))
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	web.url = u
	return web
}

func (web *fakeWeb) received() []webCall {
	web.mu.Lock()
	defer web.mu.Unlock()
	return append([]webCall(nil), web.calls...)
}

func mustWebRoutes(t *testing.T, auth *stubAuth, web *fakeWeb, core *fakeCore) http.Handler {
	t.Helper()
	tp := noop.NewTracerProvider()
	upstreams := proxy.ExtClients{
		Core:        proxy.NewProxy(core.url, proxy.NewTransport(tp, time.Second, slog.LevelInfo), testConfig()),
		MOKImporter: http.NotFoundHandler(),
		Web:         proxy.NewProxy(web.url, proxy.NewTransport(tp, time.Second, slog.LevelDebug), testConfig()),
	}
	h, err := RoutesHandler(tp, auth, testConfig(), upstreams)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestWebUIServesEveryPathOutsideAPIAndAuth(t *testing.T) {
	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/"},
		{http.MethodGet, "/workspaces"},
		{http.MethodGet, "/assets/index-abc123.js"},
		{http.MethodGet, "/healthz/"},
		{http.MethodHead, "/workspaces"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			auth, web, core := &stubAuth{}, newFakeWeb(t), newFakeCore(t)
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("Cookie", "__Host-fintrace-session=opaque")

			rec := httptest.NewRecorder()
			mustWebRoutes(t, auth, web, core).ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want the web UI's 200", rec.Code)
			}
			calls := web.received()
			if len(calls) != 1 || calls[0].method != tt.method || calls[0].path != tt.path {
				t.Fatalf("the web UI received %+v, want one %s %s", calls, tt.method, tt.path)
			}
			if calls[0].cookie != "" || calls[0].auth != "" {
				t.Errorf("the web UI got Cookie %q and Authorization %q, want neither", calls[0].cookie, calls[0].auth)
			}
			if ran := auth.ran(); len(ran) != 0 {
				t.Errorf("authentication ran %v for a static file, want nothing", ran)
			}
		})
	}
}

func TestWebUINeverAnswersForAPIOrAuth(t *testing.T) {
	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/unknown"},
		{http.MethodGet, "/api/"},
		{http.MethodGet, "/auth/unknown"},
		{http.MethodGet, "/auth/logout"},
		{http.MethodPatch, "/api/v1/workspaces"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			web, core := newFakeWeb(t), newFakeCore(t)
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("Origin", testConfig().PublicOrigin.String())

			rec := httptest.NewRecorder()
			mustWebRoutes(t, &stubAuth{}, web, core).ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rec.Code)
			}
			var body struct{ Code string }
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != "NOT_FOUND" {
				t.Errorf("body %q, want problem+json with code NOT_FOUND", rec.Body.String())
			}
			if calls := web.received(); len(calls) != 0 {
				t.Errorf("the web UI received %+v, want nothing", calls)
			}
			if calls := core.received(); len(calls) != 0 {
				t.Errorf("Core received %+v, want nothing", calls)
			}
		})
	}
}

func TestWebUIIsGetOnly(t *testing.T) {
	web := newFakeWeb(t)
	req := httptest.NewRequest(http.MethodPost, "/workspaces", nil)
	req.Header.Set("Origin", testConfig().PublicOrigin.String())

	rec := httptest.NewRecorder()
	mustWebRoutes(t, &stubAuth{}, web, newFakeCore(t)).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q, want %q", got, "GET, HEAD")
	}
	if calls := web.received(); len(calls) != 0 {
		t.Errorf("the web UI received %+v, want nothing", calls)
	}
}

// Vite's hot reload opens a WebSocket on the page's origin; the upgrade is a GET the proxy passes on.
func TestWebUIGetsAWebSocketUpgrade(t *testing.T) {
	web := newFakeWeb(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	mustWebRoutes(t, &stubAuth{}, web, newFakeCore(t)).ServeHTTP(httptest.NewRecorder(), req)

	calls := web.received()
	if len(calls) != 1 || calls[0].upgrade != "websocket" {
		t.Errorf("the web UI received %+v, want one request asking to upgrade to websocket", calls)
	}
}
