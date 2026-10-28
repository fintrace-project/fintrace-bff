package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/fintrace-project/fintrace-bff/internal/server/proxy"
)

const testBearer = "Bearer test-token"

const (
	pathSession = "session"
	pathToken   = "token"
	pathSignOut = "sign-out"
)

type stubAuth struct {
	mu    sync.Mutex
	paths []string
}

func (*stubAuth) SignIn(http.ResponseWriter, *http.Request)    {}
func (*stubAuth) Callback(http.ResponseWriter, *http.Request)  {}
func (a *stubAuth) SignOut(http.ResponseWriter, *http.Request) { a.record(pathSignOut) }

func (a *stubAuth) BearerFromSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.record(pathSession)
		out := r.Clone(r.Context())
		out.Header.Set("Authorization", testBearer)
		next.ServeHTTP(w, out)
	})
}

func (a *stubAuth) VerifyBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.record(pathToken)
		next.ServeHTTP(w, r)
	})
}

func (a *stubAuth) record(path string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.paths = append(a.paths, path)
}

func (a *stubAuth) ran() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.paths...)
}

type coreCall struct {
	path        string
	auth        string
	traceparent string
}

type fakeCore struct {
	url   *url.URL
	mu    sync.Mutex
	calls []coreCall
}

func newFakeCore(t *testing.T) *fakeCore {
	t.Helper()
	c := &fakeCore{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.calls = append(c.calls, coreCall{path: r.URL.Path, auth: r.Header.Get("Authorization"),
			traceparent: r.Header.Get("Traceparent")})
		c.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.url = u
	return c
}

func (c *fakeCore) received() []coreCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]coreCall(nil), c.calls...)
}

func mustAPIRoutes(t *testing.T, tp trace.TracerProvider, auth *stubAuth, core *fakeCore) http.Handler {
	t.Helper()
	upstreams := proxy.ExtClients{
		Core:        proxy.NewProxy(core.url, proxy.NewTransport(tp, time.Second), testConfig()),
		MOKImporter: http.NotFoundHandler(),
	}
	h, err := RoutesHandler(tp, auth, testConfig(), upstreams)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCoreSeesTheBFFsTraceNotTheCallers(t *testing.T) {
	tp, sr := newRecordingProvider(t)
	core := newFakeCore(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	req.Header.Set("Traceparent", "00-"+incomingTraceID+"-00f067aa0ba902b7-01")

	rec := httptest.NewRecorder()
	mustAPIRoutes(t, tp, &stubAuth{}, core).ServeHTTP(rec, req)

	calls := core.received()
	if len(calls) != 1 {
		t.Fatalf("Core received %d requests, status = %d; want 1", len(calls), rec.Code)
	}
	parts := strings.Split(calls[0].traceparent, "-")
	if len(parts) != 4 {
		t.Fatalf("Core's traceparent = %q, want version-traceid-spanid-flags", calls[0].traceparent)
	}
	if parts[1] == incomingTraceID {
		t.Fatal("Core continued the caller's trace, want the BFF's own")
	}

	var server trace.SpanContext
	for _, s := range sr.Ended() {
		if s.SpanKind() == trace.SpanKindServer {
			server = s.SpanContext()
		}
	}
	if !server.IsValid() {
		t.Fatal("no server span recorded")
	}
	if parts[1] != server.TraceID().String() {
		t.Errorf("Core's trace id = %s, want the BFF's %s", parts[1], server.TraceID())
	}
}

func TestRoutesHandlerProxiesListedCoreRoutesOnly(t *testing.T) {
	tp, _ := newRecordingProvider(t)
	core := newFakeCore(t)
	h := mustAPIRoutes(t, tp, &stubAuth{}, core)

	for _, path := range []string{"/api/v1/workspaces", "/admin/api/v1/workspaces/id-1/replay"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}

	calls := core.received()
	if len(calls) != 1 || calls[0].path != "/api/v1/workspaces" {
		t.Fatalf("Core received %+v, want only GET /api/v1/workspaces", calls)
	}
	if calls[0].auth != testBearer {
		t.Errorf("Authorization = %q, want the bearer's %q", calls[0].auth, testBearer)
	}
}

func TestRoutesHandlerPutsTheCallersTokenAheadOfTheSession(t *testing.T) {
	session := &http.Cookie{Name: "__Host-fintrace-session", Value: "session-id-1"}
	tests := []struct {
		name          string
		authorization string
		cookie        bool
		wantPath      string
		wantUpstream  string
	}{
		{name: "a token alone", authorization: "Bearer caller-token",
			wantPath: pathToken, wantUpstream: "Bearer caller-token"},
		{name: "a token and a cookie", authorization: "Bearer caller-token", cookie: true,
			wantPath: pathToken, wantUpstream: "Bearer caller-token"},
		{name: "a lower-case scheme", authorization: "bearer caller-token",
			wantPath: pathToken, wantUpstream: "bearer caller-token"},
		{name: "a cookie alone", cookie: true,
			wantPath: pathSession, wantUpstream: testBearer},
		{name: "Basic and a cookie", authorization: "Basic dXNlcjpwYXNz", cookie: true,
			wantPath: pathSession, wantUpstream: testBearer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp, _ := newRecordingProvider(t)
			core := newFakeCore(t)
			auth := &stubAuth{}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			if tt.cookie {
				req.AddCookie(session)
			}

			rec := httptest.NewRecorder()
			mustAPIRoutes(t, tp, auth, core).ServeHTTP(rec, req)

			if got := auth.ran(); !slices.Equal(got, []string{tt.wantPath}) {
				t.Errorf("paths run = %q, want only %q", got, tt.wantPath)
			}
			calls := core.received()
			if len(calls) != 1 {
				t.Fatalf("Core received %d requests, status = %d; want 1", len(calls), rec.Code)
			}
			if calls[0].auth != tt.wantUpstream {
				t.Errorf("Core's Authorization = %q, want %q", calls[0].auth, tt.wantUpstream)
			}
		})
	}
}

func TestRoutesHandlerLetsABearerWriteWithoutAnOrigin(t *testing.T) {
	tp, _ := newRecordingProvider(t)
	core := newFakeCore(t)
	auth := &stubAuth{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer caller-token")

	rec := httptest.NewRecorder()
	mustAPIRoutes(t, tp, auth, core).ServeHTTP(rec, req)

	if calls := core.received(); len(calls) != 1 {
		t.Fatalf("Core received %d requests, status = %d; want 1, as fintrace-smoke sends no Origin", len(calls), rec.Code)
	}
	if got := auth.ran(); !slices.Equal(got, []string{pathToken}) {
		t.Errorf("paths run = %q, want only %q", got, pathToken)
	}
}

func TestRoutesHandlerNeverSignsOutThroughAnAPIPath(t *testing.T) {
	tp, _ := newRecordingProvider(t)
	auth := &stubAuth{}
	// Exempt from CSRF by its prefix, so only the mux's redirect of the unclean path keeps it from sign-out.
	req := httptest.NewRequest(http.MethodPost, "/api/../auth/logout", nil)
	req.Header.Set("Authorization", "Bearer caller-token")
	req.Header.Set("Origin", "https://evil.example")

	rec := httptest.NewRecorder()
	mustAPIRoutes(t, tp, auth, newFakeCore(t)).ServeHTTP(rec, req)

	if got := auth.ran(); len(got) != 0 {
		t.Errorf("paths run = %q, want none", got)
	}
	// A client following the 307 sends a fresh request to /auth/logout, which the CSRF check covers
	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want the mux's %d to the clean path", rec.Code, http.StatusTemporaryRedirect)
	}
}
