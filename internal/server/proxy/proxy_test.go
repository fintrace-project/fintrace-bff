package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/config"
	"github.com/fintrace-project/fintrace-bff/internal/httperr"
)

type arrived struct {
	method string
	path   string
	query  string
	host   string
	header http.Header
	body   string
}

type fakeCore struct {
	srv *httptest.Server
	url *url.URL

	mu    sync.Mutex
	calls []arrived
}

func newFakeCore(t *testing.T, respond http.HandlerFunc) *fakeCore {
	t.Helper()
	c := &fakeCore{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.calls = append(c.calls, arrived{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery,
			host: r.Host, header: r.Header.Clone(), body: string(body)})
		c.mu.Unlock()
		respond(w, r)
	}))
	t.Cleanup(c.srv.Close)
	u, err := url.Parse(c.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.url = u
	return c
}

func (c *fakeCore) only(t *testing.T) arrived {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.calls) != 1 {
		t.Fatalf("Core received %d requests, want 1", len(c.calls))
	}
	return c.calls[0]
}

func wantHTTPError(t *testing.T, rec *httptest.ResponseRecorder, status int, code httperr.Code) {
	t.Helper()
	if rec.Code != status {
		t.Errorf("status = %d, want %d", rec.Code, status)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var body struct{ Code httperr.Code }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not JSON: %v", rec.Body.String(), err)
	}
	if body.Code != code {
		t.Errorf("code = %q, want %q", body.Code, code)
	}
}

func noContent(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

var publicOrigin = &url.URL{Scheme: "https", Host: "fintrace.example"}

func testConfig() config.Config {
	return config.Config{PublicOrigin: publicOrigin}
}

func proxyTo(target *url.URL, transport http.RoundTripper, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	NewProxy(target, transport, testConfig()).ServeHTTP(rec, req)
	return rec
}

func TestProxyForwardsTheCallIntact(t *testing.T) {
	core := newFakeCore(t, noContent)
	req := httptest.NewRequest(http.MethodPut, "http://bff.example/api/v1/workspaces/id-1?version=3",
		strings.NewReader(`{"name":"Home"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer access-1")

	rec := proxyTo(core.url, http.DefaultTransport, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want Core's %d", rec.Code, http.StatusNoContent)
	}
	got := core.only(t)
	if got.method != http.MethodPut || got.path != "/api/v1/workspaces/id-1" || got.query != "version=3" {
		t.Errorf("Core got %s %s?%s, want PUT /api/v1/workspaces/id-1?version=3", got.method, got.path, got.query)
	}
	if got.body != `{"name":"Home"}` {
		t.Errorf("body = %q, want it unchanged", got.body)
	}
	if ct := got.header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if a := got.header.Get("Authorization"); a != "Bearer access-1" {
		t.Errorf("Authorization = %q, want it passed through", a)
	}
	if got.host != core.url.Host {
		t.Errorf("Host = %q, want Core's %q, not the BFF's", got.host, core.url.Host)
	}
}

func TestProxyJoinsTheTargetsBasePath(t *testing.T) {
	tests := []struct {
		name string
		base string
	}{
		{name: "a base path", base: "/base"},
		{name: "a base path with a trailing slash", base: "/base/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core := newFakeCore(t, noContent)
			target := *core.url
			target.Path = tt.base

			proxyTo(&target, http.DefaultTransport, httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil))

			if got := core.only(t).path; got != "/base/api/v1/workspaces" {
				t.Errorf("Core got %s, want /base/api/v1/workspaces", got)
			}
		})
	}
}

func TestProxyStripsWhatCoreMustNotSee(t *testing.T) {
	core := newFakeCore(t, noContent)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-fintrace-session", Value: "session-id"})
	req.AddCookie(&http.Cookie{Name: "other", Value: "x"})
	req.Header.Set("Traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	req.Header.Set("Tracestate", "vendor=chosen-by-the-caller")
	req.Header.Set("Baggage", "user=chosen-by-the-caller")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("Forwarded", "for=203.0.113.7")

	proxyTo(core.url, http.DefaultTransport, req)

	got := core.only(t)
	for _, h := range []string{"Cookie", "Traceparent", "Tracestate", "Baggage",
		"X-Forwarded-For", "X-Forwarded-Host", "Forwarded"} {
		if v := got.header.Values(h); len(v) != 0 {
			t.Errorf("%s = %q reached Core, want it stripped", h, v)
		}
	}
}

func TestProxyLeavesTheIncomingRequestUnchanged(t *testing.T) {
	core := newFakeCore(t, noContent)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-fintrace-session", Value: "session-id"})

	proxyTo(core.url, http.DefaultTransport, req)

	if req.Header.Get("Cookie") == "" {
		t.Error("the incoming request lost its Cookie, want only the outbound one stripped")
	}
}

func TestProxyPassesCoresErrorBackUnchanged(t *testing.T) {
	const problem = `{"type":"about:blank","title":"Conflict","status":409,"detail":"version mismatch"}`
	core := newFakeCore(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, problem)
	})

	rec := proxyTo(core.url, http.DefaultTransport, httptest.NewRequest(http.MethodDelete, "/api/v1/workspaces/id-1?version=1", nil))

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	if body := rec.Body.String(); body != problem {
		t.Errorf("body = %q, want %q", body, problem)
	}
}

func TestProxyDropsCoresSetCookieAndKeepsTheRest(t *testing.T) {
	core := newFakeCore(t, func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "planted", Value: "x"})
		w.Header().Set("Location", "/api/v1/workspaces/id-1")
		w.WriteHeader(http.StatusCreated)
	})

	rec := proxyTo(core.url, http.DefaultTransport, httptest.NewRequest(http.MethodPost, "/api/v1/workspaces", nil))

	if sc := rec.Header().Values("Set-Cookie"); len(sc) != 0 {
		t.Errorf("Set-Cookie = %q reached the browser, want it dropped", sc)
	}
	if loc := rec.Header().Get("Location"); loc != "/api/v1/workspaces/id-1" {
		t.Errorf("Location = %q, want Core's header kept", loc)
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
}

func TestProxyAnswers502WhenCoreIsDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(noContent))
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()

	rec := proxyTo(target, http.DefaultTransport, httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil))

	wantHTTPError(t, rec, http.StatusBadGateway, httperr.UpstreamUnavailable)
}

func TestProxyAnswers504WhenCoreIsTooSlow(t *testing.T) {
	core := newFakeCore(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	transport := &http.Transport{ResponseHeaderTimeout: 50 * time.Millisecond}
	t.Cleanup(transport.CloseIdleConnections)

	rec := proxyTo(core.url, transport, httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil))

	wantHTTPError(t, rec, http.StatusGatewayTimeout, httperr.UpstreamTimeout)
}

func TestProxyRewritesCoresOwnLocationAndStillDropsSetCookie(t *testing.T) {
	var core *fakeCore
	core = newFakeCore(t, func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "planted", Value: "x"})
		w.Header().Set("Location", core.url.String()+"/api/v1/workspaces/id-1")
		w.WriteHeader(http.StatusCreated)
	})

	rec := proxyTo(core.url, http.DefaultTransport, httptest.NewRequest(http.MethodPost, "/api/v1/workspaces", nil))

	if loc := rec.Header().Get("Location"); loc != "https://fintrace.example/api/v1/workspaces/id-1" {
		t.Errorf("Location = %q, want Core's rewritten to the public origin", loc)
	}
	if sc := rec.Header().Values("Set-Cookie"); len(sc) != 0 {
		t.Errorf("Set-Cookie = %q reached the browser, want it dropped beside the rewrite", sc)
	}
}

func TestAdjustLocation(t *testing.T) {
	core := &url.URL{Scheme: "http", Host: "fintrace-core:8080"}
	tests := []struct {
		name     string
		target   *url.URL
		location string
		want     string
	}{
		{name: "naming the upstream", target: core,
			location: "http://fintrace-core:8080/api/v1/workspaces/id-1",
			want:     "https://fintrace.example/api/v1/workspaces/id-1"},
		{name: "query and fragment kept", target: core,
			location: "http://fintrace-core:8080/api/v1/operations?page=2#top",
			want:     "https://fintrace.example/api/v1/operations?page=2#top"},
		{name: "the upstream's host in another case", target: core,
			location: "http://FINTRACE-CORE:8080/api/v1/workspaces/id-1",
			want:     "https://fintrace.example/api/v1/workspaces/id-1"},
		{name: "the target's base path stripped",
			target:   &url.URL{Scheme: "http", Host: "fintrace-core:8080", Path: "/base"},
			location: "http://fintrace-core:8080/base/api/v1/workspaces/id-1",
			want:     "https://fintrace.example/api/v1/workspaces/id-1"},
		{name: "the target's base path with a trailing slash stripped",
			target:   &url.URL{Scheme: "http", Host: "fintrace-core:8080", Path: "/base/"},
			location: "http://fintrace-core:8080/base/api/v1/workspaces/id-1",
			want:     "https://fintrace.example/api/v1/workspaces/id-1"},
		{name: "exactly the base path",
			target:   &url.URL{Scheme: "http", Host: "fintrace-core:8080", Path: "/base"},
			location: "http://fintrace-core:8080/base",
			want:     "https://fintrace.example"},
		{name: "a path that only starts like the base path",
			target:   &url.URL{Scheme: "http", Host: "fintrace-core:8080", Path: "/base"},
			location: "http://fintrace-core:8080/basement/x",
			want:     "https://fintrace.example/basement/x"},
		{name: "relative, untouched", target: core,
			location: "/api/v1/workspaces/id-1", want: "/api/v1/workspaces/id-1"},
		{name: "another host, untouched", target: core,
			location: "https://elsewhere.example/x", want: "https://elsewhere.example/x"},
		{name: "the upstream's host on another scheme, untouched", target: core,
			location: "https://fintrace-core:8080/x", want: "https://fintrace-core:8080/x"},
		{name: "the upstream's name on another port, untouched", target: core,
			location: "http://fintrace-core/x", want: "http://fintrace-core/x"},
		{name: "malformed, untouched", target: core,
			location: "http://fintrace-core:8080/%zz", want: "http://fintrace-core:8080/%zz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{"Location": {tt.location}},
				Request: httptest.NewRequest(http.MethodPost, "/api/v1/workspaces", nil)}

			adjustLocation(resp, publicOrigin, tt.target)

			if got := resp.Header.Get("Location"); got != tt.want {
				t.Errorf("Location = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAdjustLocationAddsNoneWhereThereWasNone(t *testing.T) {
	resp := &http.Response{Header: http.Header{},
		Request: httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil)}

	adjustLocation(resp, publicOrigin, &url.URL{Scheme: "http", Host: "fintrace-core:8080"})

	if v, ok := resp.Header["Location"]; ok {
		t.Errorf("Location = %q, want no header", v)
	}
}
