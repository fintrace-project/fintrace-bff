package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/fintrace-project/fintrace-bff/internal/config"
	"github.com/fintrace-project/fintrace-bff/internal/csp"
	"github.com/fintrace-project/fintrace-bff/internal/httperr"
)

const (
	nonce = "N0NCE"
	etag  = `"built-1"`
)

var page = `<!doctype html><meta property="csp-nonce" nonce="` + csp.Placeholder + `">` +
	`<link rel="stylesheet" nonce="` + csp.Placeholder + `" href="/assets/index.css">`

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := io.WriteString(gz, s); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// serving answers like nginx does: the body as given, revalidated by ETag.
func serving(contentType, encoding string, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", "Tue, 10 Nov 2026 10:00:00 GMT")
		w.Header().Set("Cache-Control", "no-cache")
		if encoding != "" {
			w.Header().Set("Content-Encoding", encoding)
		}
		_, _ = w.Write(body)
	}
}

// A browser's request: it accepts gzip, and the middleware has stored the nonce unless it is empty.
func browserRequest(method, encoding, withNonce string) *http.Request {
	req := httptest.NewRequest(method, "/workspaces", nil)
	req.Header.Set("Accept-Encoding", encoding)
	if withNonce != "" {
		req = req.WithContext(csp.WithNonce(req.Context(), withNonce))
	}
	return req
}

func proxyWithCSP(target *url.URL, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	WithCSP(NewProxy(target, http.DefaultTransport, testConfig())).ServeHTTP(rec, req)
	return rec
}

func TestWithCSPWritesTheNonceIntoThePage(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
		body     []byte
	}{
		{name: "plain", body: []byte(page)},
		{name: "gzipped, as nginx serves it", encoding: "gzip", body: gzipped(t, page)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			web := newFakeCore(t, serving("text/html; charset=utf-8", tt.encoding, tt.body))

			rec := proxyWithCSP(web.url, browserRequest(http.MethodGet, "gzip", nonce))

			want := strings.ReplaceAll(page, csp.Placeholder, nonce)
			if rec.Code != http.StatusOK || rec.Body.String() != want {
				t.Fatalf("%d %q, want 200 %q", rec.Code, rec.Body.String(), want)
			}
			if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(want)) {
				t.Errorf("Content-Length = %q, want %d, the rewritten body's", got, len(want))
			}
			if got := rec.Header().Get("Content-Encoding"); got != "" {
				t.Errorf("Content-Encoding = %q on a body sent plain, want none", got)
			}
			// A revalidated 304 would keep a page naming an earlier response's nonce
			for _, h := range []string{"ETag", "Last-Modified"} {
				if got := rec.Header().Values(h); len(got) != 0 {
					t.Errorf("%s = %q, want none", h, got)
				}
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}

func TestWithCSPLeavesTheRestAlone(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		contentType string
		status      int
		nonce       string
		wantBody    string
	}{
		{name: "a script naming the placeholder", method: http.MethodGet, contentType: "text/javascript",
			status: http.StatusOK, nonce: nonce, wantBody: page},
		{name: "the page beside a configured policy", method: http.MethodGet, contentType: "text/html",
			status: http.StatusOK, wantBody: page},
		{name: "HEAD of the page", method: http.MethodHead, contentType: "text/html",
			status: http.StatusOK, nonce: nonce},
		{name: "a 304 for the page", method: http.MethodGet, contentType: "text/html",
			status: http.StatusNotModified, nonce: nonce},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			web := newFakeCore(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				w.Header().Set("ETag", etag)
				w.Header().Set("Cache-Control", "no-cache")
				w.WriteHeader(tt.status)
				if tt.status == http.StatusOK && r.Method == http.MethodGet {
					_, _ = io.WriteString(w, page)
				}
			})

			rec := proxyWithCSP(web.url, browserRequest(tt.method, "gzip", tt.nonce))

			if rec.Code != tt.status || rec.Body.String() != tt.wantBody {
				t.Errorf("%d %q, want %d %q unchanged", rec.Code, rec.Body.String(), tt.status, tt.wantBody)
			}
			if got := rec.Header().Get("ETag"); got != etag {
				t.Errorf("ETag = %q, want the web UI's %q kept", got, etag)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
				t.Errorf("Cache-Control = %q, want the web UI's no-cache kept", got)
			}
		})
	}
}

// A page the BFF cannot write the nonce into is refused rather than sent naming none.
func TestWithCSPAnswers502ForAPageItCannotRead(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
		body     []byte
	}{
		{name: "an encoding it cannot undo", encoding: "br", body: []byte("brotli bytes")},
		{name: "a broken gzip", encoding: "gzip", body: []byte("not gzip at all")},
		{name: "larger than any index.html", body: bytes.Repeat([]byte("a"), maxHTMLBytes+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			web := newFakeCore(t, serving("text/html", tt.encoding, tt.body))

			rec := proxyWithCSP(web.url, browserRequest(http.MethodGet, "gzip, br", nonce))

			wantHTTPError(t, rec, http.StatusBadGateway, httperr.UpstreamUnavailable)
		})
	}
}

func TestWithCSPKeepsTheProxysOwnStep(t *testing.T) {
	web := newFakeCore(t, func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "planted", Value: "x"})
		w.Header().Set("Content-Security-Policy", "default-src *")
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, page)
	})

	rec := proxyWithCSP(web.url, browserRequest(http.MethodGet, "gzip", nonce))

	if sc := rec.Header().Values("Set-Cookie"); len(sc) != 0 {
		t.Errorf("Set-Cookie = %q reached the browser, want it dropped", sc)
	}
	if got := rec.Header().Values("Content-Security-Policy"); len(got) != 0 {
		t.Errorf("the web UI's own policy %q reached the browser, want it dropped", got)
	}
	if !strings.Contains(rec.Body.String(), nonce) {
		t.Errorf("body %q, want the nonce written beside the proxy's own step", rec.Body.String())
	}
}

func TestOnlyTheWebUIsPageGetsTheNonce(t *testing.T) {
	core := newFakeCore(t, serving("text/html", "", []byte(page)))
	web := newFakeCore(t, serving("text/html", "", []byte(page)))
	cfg := config.Config{PublicOrigin: publicOrigin, CoreURL: core.url, MOKImporterURL: core.url, WebURL: web.url}
	transports := UpstreamTransports{Core: http.DefaultTransport, MOKImporter: http.DefaultTransport,
		Web: http.DefaultTransport}
	proxies := MakeUpstreamProxies(cfg, transports)

	tests := []struct {
		name     string
		upstream http.Handler
		want     string
	}{
		{name: "Core", upstream: proxies.Core, want: page},
		{name: "the importer", upstream: proxies.MOKImporter, want: page},
		{name: "the web UI", upstream: proxies.Web, want: strings.ReplaceAll(page, csp.Placeholder, nonce)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.upstream.ServeHTTP(rec, browserRequest(http.MethodGet, "gzip", nonce))

			if rec.Body.String() != tt.want {
				t.Errorf("body = %q, want %q", rec.Body.String(), tt.want)
			}
		})
	}
}
