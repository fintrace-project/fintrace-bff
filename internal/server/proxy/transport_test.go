package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func newRecordingProvider(t *testing.T) (*sdktrace.TracerProvider, *tracetest.SpanRecorder) {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	return tp, sr
}

// traceparent is version-traceid-spanid-flags (W3C Trace Context §3.2)
func parseTraceparent(t *testing.T, h string) (traceID, spanID string) {
	t.Helper()
	parts := strings.Split(h, "-")
	if len(parts) != 4 {
		t.Fatalf("traceparent = %q, want version-traceid-spanid-flags", h)
	}
	return parts[1], parts[2]
}

func TestTransportCarriesTheCallersTraceInAClientSpan(t *testing.T) {
	tp, sr := newRecordingProvider(t)
	core := newFakeCore(t, noContent)
	ctx, parent := tp.Tracer("test").Start(t.Context(), "server")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, core.srv.URL+"/api/v1/workspaces", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := NewTransport(tp, time.Second, slog.LevelInfo).RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	_ = resp.Body.Close()
	parent.End()

	traceID, spanID := parseTraceparent(t, core.only(t).header.Get("Traceparent"))
	if want := parent.SpanContext().TraceID().String(); traceID != want {
		t.Errorf("trace id = %s, want the caller's %s", traceID, want)
	}
	if spanID == parent.SpanContext().SpanID().String() {
		t.Error("span id is the caller's, want a client span of its own")
	}

	var client sdktrace.ReadOnlySpan
	for _, s := range sr.Ended() {
		if s.SpanKind() == trace.SpanKindClient {
			client = s
		}
	}
	if client == nil {
		t.Fatal("no client span recorded")
	}
	if client.SpanContext().SpanID().String() != spanID {
		t.Errorf("Core got span %s, want the client span %s", spanID, client.SpanContext().SpanID())
	}
	if client.Parent().SpanID() != parent.SpanContext().SpanID() {
		t.Errorf("client span's parent = %s, want the caller's span", client.Parent().SpanID())
	}
}

func TestTransportAppliesTheResponseHeaderTimeout(t *testing.T) {
	tp, _ := newRecordingProvider(t)
	core := newFakeCore(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, core.srv.URL+"/api/v1/workspaces", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := NewTransport(tp, 50*time.Millisecond, slog.LevelInfo).RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("RoundTrip() succeeded, want a timeout")
	}
	if ne, ok := errors.AsType[net.Error](err); !ok || !ne.Timeout() {
		t.Errorf("RoundTrip() error = %v, want a net.Error that is a timeout", err)
	}
}

func TestTransportLeavesTheDefaultTransportAlone(t *testing.T) {
	tp, _ := newRecordingProvider(t)
	before := http.DefaultTransport.(*http.Transport).ResponseHeaderTimeout

	NewTransport(tp, 50*time.Millisecond, slog.LevelInfo)

	if got := http.DefaultTransport.(*http.Transport).ResponseHeaderTimeout; got != before {
		t.Errorf("http.DefaultTransport's ResponseHeaderTimeout = %v, want %v unchanged", got, before)
	}
}
