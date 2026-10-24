package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace/noop"

	"github.com/fintrace-project/fintrace-bff/internal/config"
	"github.com/fintrace-project/fintrace-bff/internal/session"
)

func startServe(t *testing.T, srv *http.Server) (addr string, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	ln, err := listen(srv)
	if err != nil {
		t.Fatalf("listen() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() { errCh <- serve(ctx, srv, ln) }()
	return "http://" + ln.Addr().String(), cancel, errCh
}

func waitServe(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("serve() did not return after the context was cancelled")
		return nil
	}
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("reading %s: %v", url, err)
	}
	return resp.StatusCode, string(body)
}

func TestServeAnswersUntilCancelledThenShutsDownCleanly(t *testing.T) {
	addr, cancel, done := startServe(t, newHTTPServer(config.Config{ListenAddr: "127.0.0.1:0"}, noop.NewTracerProvider(), &session.Auth{}))

	if code, body := get(t, addr+"/healthz"); code != http.StatusOK || body != `{"status":"UP"}` {
		t.Fatalf("GET /healthz = %d %q, want 200 {\"status\":\"UP\"}", code, body)
	}

	cancel()
	if err := waitServe(t, done); err != nil {
		t.Fatalf("serve() = %v, want nil after a cancelled context", err)
	}
	if _, err := http.Get(addr + "/healthz"); err == nil {
		t.Error("the server still answers after shutdown")
	}
}

func TestServeLetsARequestInFlightFinish(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := &http.Server{
		Addr: "127.0.0.1:0",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(entered)
			<-release
			_, _ = io.WriteString(w, "finished")
		}),
		ReadHeaderTimeout: time.Second,
	}
	addr, cancel, done := startServe(t, srv)

	type result struct {
		code int
		body string
		err  error
	}
	resCh := make(chan result, 1)
	// t.Fatal may only be called from the test's own goroutine, so this one reports back instead.
	go func() {
		resp, err := http.Get(addr + "/slow")
		if err != nil {
			resCh <- result{err: err}
			return
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		resCh <- result{code: resp.StatusCode, body: string(body), err: err}
	}()
	<-entered

	cancel()
	select {
	case err := <-done:
		t.Fatalf("serve() returned %v while a request was still in flight", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	if res := <-resCh; res.err != nil || res.code != http.StatusOK || res.body != "finished" {
		t.Errorf("in-flight request = %d %q (err %v), want 200 \"finished\"", res.code, res.body, res.err)
	}
	if err := waitServe(t, done); err != nil {
		t.Fatalf("serve() = %v, want nil", err)
	}
}

func TestServeReportsAServerThatCannotRun(t *testing.T) {
	srv := newHTTPServer(config.Config{ListenAddr: "127.0.0.1:0"}, noop.NewTracerProvider(), &session.Auth{})
	ln, err := listen(srv)
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()

	err = serve(t.Context(), srv, ln)
	if err == nil || !strings.HasPrefix(err.Error(), "server: ") {
		t.Fatalf("serve() on a closed listener = %v, want a server error", err)
	}
}

func TestListenRejectsATakenPort(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = taken.Close() })

	_, err = listen(newHTTPServer(config.Config{ListenAddr: taken.Addr().String()}, noop.NewTracerProvider(), &session.Auth{}))
	if err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("listen() on a taken port = %v, want address already in use", err)
	}
}
