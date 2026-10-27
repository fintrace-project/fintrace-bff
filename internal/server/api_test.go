package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/fintrace-project/fintrace-bff/internal/server/proxy"
)

const testBearer = "Bearer test-token"

type stubAuth struct{}

func (stubAuth) SignIn(http.ResponseWriter, *http.Request)   {}
func (stubAuth) Callback(http.ResponseWriter, *http.Request) {}
func (stubAuth) SignOut(http.ResponseWriter, *http.Request)  {}

func (stubAuth) BearerFromSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := r.Clone(r.Context())
		out.Header.Set("Authorization", testBearer)
		next.ServeHTTP(w, out)
	})
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

func mustAPIRoutes(t *testing.T, tp trace.TracerProvider, core *fakeCore) http.Handler {
	t.Helper()
	h, err := RoutesHandler(tp, stubAuth{}, proxy.New(core.url, proxy.NewTransport(tp, time.Second)), testConfig())
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
	mustAPIRoutes(t, tp, core).ServeHTTP(rec, req)

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
	h := mustAPIRoutes(t, tp, core)

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
