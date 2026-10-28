package proxy

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/httperr"
)

const importPath = "/api/v1/workspaces/id-1/import"

// The importer route as RoutesHandler builds it, in front of a fake importer
func newImporterMux(t *testing.T, respond http.HandlerFunc) (*http.ServeMux, *fakeCore) {
	t.Helper()
	importer := newFakeCore(t, respond)
	mux := http.NewServeMux()
	RegisterImporterRoutes(mux, stubBearer, NewProxy(importer.url, http.DefaultTransport, testConfig()))
	return mux, importer
}

func multipartDump(t *testing.T, content string) (body *bytes.Buffer, contentType string) {
	t.Helper()
	body = &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	part, err := mw.CreateFormFile("file", "dump.mok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, content); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return body, mw.FormDataContentType()
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestTheImportRouteReachesOnlyTheImporter(t *testing.T) {
	mux := http.NewServeMux()
	core, importer := &upstreamRecorder{}, &upstreamRecorder{}
	RegisterCoreRoutes(mux, stubBearer, core)
	RegisterImporterRoutes(mux, stubBearer, importer)

	serve(mux, http.MethodPost, importPath)
	rec := serve(mux, http.MethodGet, importPath)

	if len(importer.calls) != 1 || len(core.calls) != 0 {
		t.Errorf("importer called %d times, Core %d; want 1 and 0", len(importer.calls), len(core.calls))
	}
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestUploadReachesTheImporterIntact(t *testing.T) {
	mux, importer := newImporterMux(t, noContent)
	body, contentType := multipartDump(t, "SQLite format 3\x00 and the rest of the dump")
	want := body.String()
	req := httptest.NewRequest(http.MethodPost, importPath, body)
	req.Header.Set("Content-Type", contentType)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want the importer's %d", rec.Code, http.StatusNoContent)
	}
	got := importer.only(t)
	if got.method != http.MethodPost || got.path != importPath {
		t.Errorf("importer got %s %s, want POST %s", got.method, got.path, importPath)
	}
	if ct := got.header.Get("Content-Type"); ct != contentType {
		t.Errorf("Content-Type = %q, want %q with its boundary", ct, contentType)
	}
	if got.body != want {
		t.Errorf("body differs: got %d bytes, want %d", len(got.body), len(want))
	}
	if a := got.header.Get("Authorization"); a != testBearer {
		t.Errorf("Authorization = %q, want %q: the route is not behind the bearer", a, testBearer)
	}
}

func TestUploadIsStreamedNotBuffered(t *testing.T) {
	const chunk = 256 << 10
	firstChunkArrived := make(chan struct{})
	importer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadFull(r.Body, make([]byte, chunk)); err != nil {
			t.Errorf("reading the first chunk: %v", err)
		}
		close(firstChunkArrived)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(importer.Close)
	target, err := url.Parse(importer.URL)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterImporterRoutes(mux, stubBearer, NewProxy(target, http.DefaultTransport, testConfig()))

	pr, pw := io.Pipe()
	req := httptest.NewRequest(http.MethodPost, importPath, pr)
	req.ContentLength = -1
	done := make(chan *httptest.ResponseRecorder)
	go func() {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		done <- rec
	}()

	if _, err := pw.Write(make([]byte, chunk)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstChunkArrived:
	case <-time.After(5 * time.Second):
		_ = pw.CloseWithError(io.ErrUnexpectedEOF)
		t.Fatal("the importer saw nothing while the upload was still being sent: the BFF buffers it")
	}
	if _, err := pw.Write(make([]byte, chunk)); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()

	if rec := <-done; rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestUploadDeclaredTooLargeIsRefusedBeforeTheImporter(t *testing.T) {
	mux, importer := newImporterMux(t, noContent)
	req := httptest.NewRequest(http.MethodPost, importPath, strings.NewReader("small"))
	req.ContentLength = uploadMaxBytes + 1

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	wantHTTPError(t, rec, http.StatusRequestEntityTooLarge, httperr.UploadTooLarge)
	importer.mu.Lock()
	defer importer.mu.Unlock()
	if n := len(importer.calls); n != 0 {
		t.Errorf("importer called %d times, want never", n)
	}
}

func TestUploadGrowingPastTheLimitIs413(t *testing.T) {
	mux, _ := newImporterMux(t, noContent)
	req := httptest.NewRequest(http.MethodPost, importPath, io.LimitReader(zeros{}, uploadMaxBytes+1))
	req.ContentLength = -1

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	wantHTTPError(t, rec, http.StatusRequestEntityTooLarge, httperr.UploadTooLarge)
}

func TestUploadAtTheLimitIsForwarded(t *testing.T) {
	mux, importer := newImporterMux(t, noContent)
	req := httptest.NewRequest(http.MethodPost, importPath, io.LimitReader(zeros{}, uploadMaxBytes))
	req.ContentLength = -1

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want the importer's %d", rec.Code, http.StatusNoContent)
	}
	if n := len(importer.only(t).body); n != uploadMaxBytes {
		t.Errorf("importer got %d bytes, want %d", n, uploadMaxBytes)
	}
}

func TestImportersOwnAnswersPassThrough(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{name: "its own size limit", status: http.StatusRequestEntityTooLarge,
			contentType: "application/problem+json", body: `{"status":413,"code":"PAYLOAD_TOO_LARGE"}`},
		{name: "a failed job", status: http.StatusUnprocessableEntity,
			contentType: "application/json", body: `{"status":"FAILED","message":"refused"}`},
		{name: "Core not answering it", status: http.StatusGatewayTimeout,
			contentType: "application/problem+json", body: `{"status":504,"detail":"read the workspace's status"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux, _ := newImporterMux(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			})
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, importPath, strings.NewReader("dump")))

			if rec.Code != tt.status {
				t.Errorf("status = %d, want the importer's %d", rec.Code, tt.status)
			}
			if ct := rec.Header().Get("Content-Type"); ct != tt.contentType {
				t.Errorf("Content-Type = %q, want %q", ct, tt.contentType)
			}
			if rec.Body.String() != tt.body {
				t.Errorf("body = %q, want %q", rec.Body.String(), tt.body)
			}
		})
	}
}

// A server whose write timeout is far shorter than the importer's answer: only the upload route,
// which extends its deadlines, gets the answer back
func TestOnlyTheUploadRouteOutlivesTheServerTimeouts(t *testing.T) {
	importer := newFakeCore(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	mux := http.NewServeMux()
	upstream := NewProxy(importer.url, http.DefaultTransport, testConfig())
	RegisterImporterRoutes(mux, stubBearer, upstream)
	mux.Handle("POST /plain", upstream)
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.ReadTimeout = 100 * time.Millisecond
	srv.Config.WriteTimeout = 100 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Post(srv.URL+importPath, "application/octet-stream", strings.NewReader("dump"))
	if err != nil {
		t.Fatalf("upload route: %v, want the importer's answer", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("upload route: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	resp, err = srv.Client().Post(srv.URL+"/plain", "application/octet-stream", strings.NewReader("dump"))
	if err == nil {
		_ = resp.Body.Close()
		t.Errorf("plain route: status = %d, want the connection cut by the server's write timeout", resp.StatusCode)
	}
}
